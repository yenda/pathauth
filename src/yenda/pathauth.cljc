(ns yenda.pathauth
  "Pathauth bridges axiom's authorization rules (ax/*) to pg2's resolver generation.

   Transforms declarative access rules into resolver input requirements (pa/* options).
   pg2 reads these options to generate resolvers with inline permission computation.

   ## Architecture

   ```
   Axiom (ax/access rules)
       ↓
   Pathauth (derives pa/* options, provides compute-permissions)
       ↓
   pg2 (reads pa/*, computes permissions inline in resolvers)
   ```

   ## Inline Permissions (New Pattern)

   Data resolvers are UNGATED and compute permissions inline using fetched data.
   This eliminates the self-referential cycle where permission resolver needs
   entity data, but data resolver is gated on permission.

   pg2 reads pa/* options to determine:
   - What additional Pathom inputs are needed (for :when conditions on related entities)
   - What permission attrs to output (:entity/can-read?, etc.)
   - Which ops inherit from parent vs need computation

   ## Usage

   ```clojure
   (defattr issue-id :issue/id :uuid
     {::attr/identity? true
      ax/access [{:role :member :same-org true :ops #{:read}}]})
      ;; pa/* options derived automatically by augment-attributes
   ```"
  (:require
   [com.fulcrologic.rad.attributes :as-alias attr]
   [axiom :as ax]
   [axiom.pathom.access :as axiom-access]
   [axiom.pathom.analysis :as analysis]
   [clojure.set :as set]
   [malli.core :as m]
   ;; Legacy API dependencies
   [edn-query-language.core :as eql]
   [taoensso.timbre :as log]))

;; =============================================================================
;; Keys (pa/*)
;; =============================================================================

(def entity-permission
  "Boolean permission attribute required to access entity data.

   Example: :issue/can-read?

   Effect: pg2 adds this to resolver's ::pco/input.
   Resolver only fetches data when value is true."
  ::entity-permission)

(def write-permission
  "Boolean permission attribute required to modify entity.

   Example: :issue/can-write?

   Effect: Mutations check this before updating."
  ::write-permission)

(def delete-permission
  "Boolean permission attribute required to delete entity.

   Example: :issue/can-delete?

   Effect: Mutations check this before deleting."
  ::delete-permission)

(def inherit-permission
  "For relationships where all children inherit parent's permission.

   Example: :project/can-read-issues?

   Effect: pg2 gates relationship traversal. When permitted,
   all children receive true for their entity-permission."
  ::inherit-permission)

(def item-permission
  "For relationships where each child has individual permission.

   Example: :issue/can-read?

   Effect: pg2 returns all child IDs. Axiom computes permission
   per-item. Entity data only fetched for authorized items."
  ::item-permission)

(def create-permission
  "Permission to create children under this entity.

   Example: :project/can-create-issue?

   Effect: Mutations check this before creating child entities."
  ::create-permission)

;; =============================================================================
;; New Keys for Inline Permission Computation
;; =============================================================================

(def resolver-inputs
  "Additional Pathom inputs needed for permission rules.

   Derived from ax/access rules analysis. pg2 adds these to ::pco/input.

   Example: [{:group/organization [:organization/id
                                   :organization/teachers-see-all-groups]}]"
  ::resolver-inputs)

(def permission-outputs
  "Permission attrs to add to resolver output.

   Example: [:group/can-read? :group/can-write? :group/can-delete?]"
  ::permission-outputs)

(def inherited-ops
  "Operations that inherit permission from parent entity.

   Map of op -> inheritance info. pg2 passes through parent permission
   instead of computing it.

   Example:
   {:read {:path [:comment/ticket]
           :parent-id-attr :ticket/id
           :permission-attr :ticket/can-read?}}"
  ::inherited-ops)

(def computed-ops
  "Operations that need permission computation.

   Set of ops. pg2 calls compute-permissions for these.
   (All ops minus inherited-ops)"
  ::computed-ops)

(def virtual?
  "True if entity has no database table.

   When true, entity uses axiom.pathom.resolvers instead of pg2."
  ::virtual?)

(def related-attrs
  "Attrs from related entities needed for :when conditions.

   Map of ref-attr -> set of attrs to fetch from related entity.
   pg2 batch-fetches these after the main entity query.

   Example:
   {:group/organization #{:organization/id :organization/teachers-see-all-groups}}

   Means: fetch organization's teachers-see-all-groups setting for permission rules."
  ::related-attrs)

;; =============================================================================
;; Malli Schemas
;; =============================================================================

(def PermissionAttr
  "A permission attribute is a namespaced keyword ending in ?"
  [:and
   :keyword
   [:fn {:error/message "Permission attr must end with ?"}
    #(clojure.string/ends-with? (name %) "?")]])

(def EntityPermissionOptions
  "Options for entity-level permissions"
  [:map
   [::entity-permission {:optional true} PermissionAttr]
   [::write-permission {:optional true} PermissionAttr]
   [::delete-permission {:optional true} PermissionAttr]
   [::create-permission {:optional true} PermissionAttr]])

(def RelationshipPermissionOptions
  "Options for relationship permissions"
  [:map
   [::inherit-permission {:optional true} PermissionAttr]
   [::item-permission {:optional true} PermissionAttr]])

;; =============================================================================
;; Permission Attribute Naming
;; =============================================================================

(defn permission-attr
  "Generate permission attribute name from entity and action.

   (permission-attr :issue :read) => :issue/can-read?
   (permission-attr :project :create :issue) => :project/can-create-issue?"
  ([entity-key action]
   (keyword (name entity-key) (str "can-" (name action) "?")))
  ([entity-key action target]
   (keyword (name entity-key) (str "can-" (name action) "-" (name target) "?"))))

(defn entity-namespace
  "Extract entity namespace from qualified key.

   :issue/id => :issue
   :project/issues => :project"
  [qualified-key]
  (keyword (namespace qualified-key)))

;; =============================================================================
;; Rule Analysis
;; =============================================================================

(defn- extract-ops
  "Extract ops from a rule's :ops value.
   :ops can be either:
   - A set: #{:read :write :delete}
   - A map (per-op conditions): {:read {:when :org/setting}}"
  [ops-value]
  (cond
    (set? ops-value) ops-value
    (map? ops-value) (set (keys ops-value))
    :else #{}))

(defn- rules-for-op
  "Get rules that apply to a specific operation."
  [rules op]
  (filter #(contains? (:ops %) op) rules))

(defn- has-permit-rules?
  "Check if rules have any permit (non-forbid) rules for op."
  [rules op]
  (some #(and (contains? (:ops %) op)
              (not (:forbid %)))
        rules))

(defn- requires-per-item-check?
  "Determines if rules require individual permission checks per child entity.

   This drives whether pg2 uses inherit-permission or item-permission:
   - inherit-permission: Single parent check, all children inherit permission
   - item-permission: Axiom computes permission for each child individually

   Returns truthy when any permit rule contains:
   - :is - User must own specific field (e.g., :issue/reporter)
   - :member-of - User in entity's member list (e.g., :project/members)
   - :when - Custom predicate on entity data
   - :self - Entity is the user themselves
   - :inherit-from - Permission derived from related entity

   Example (inherits from parent - efficient):
     [{:role :member :same-org true :ops #{:read}}]
     => All org members can read all children

   Example (per-item check required):
     [{:is :issue/reporter :ops #{:read :write}}]
     => Only reporter of each issue can access it

   Performance impact in pg2:
   - inherit: 1 permission check for parent, bulk fetch all children
   - item: N permission checks, then fetch only authorized children"
  [rules op]
  (let [permit-rules (filter #(and (contains? (:ops %) op)
                                   (not (:forbid %)))
                             rules)]
    (some #(or (:is %)
               (:member-of %)
               (:when %)
               (:self %)
               (:inherit-from %))
          permit-rules)))

;; =============================================================================
;; Derivation Functions
;; =============================================================================

(defn derive-options
  "Given an attribute with ax/* rules, derive pa/* options.

   Input: attribute map with ax/access rules
   Output: map of pa/* keys

   Example:
   (derive-options {:ax/access [{:role :member :same-org true :ops #{:read}}
                                {:is :issue/reporter :ops #{:read :write}}]
                    ::attr/qualified-key :issue/id})
   => {::entity-permission :issue/can-read?
       ::write-permission :issue/can-write?}"
  [attribute]
  (let [rules (get attribute ax/access)
        entity-key (entity-namespace (::attr/qualified-key attribute))]
    (when (seq rules)
      (cond-> {}
        (has-permit-rules? rules :read)
        (assoc entity-permission (permission-attr entity-key :read))

        (has-permit-rules? rules :write)
        (assoc write-permission (permission-attr entity-key :write))

        (has-permit-rules? rules :delete)
        (assoc delete-permission (permission-attr entity-key :delete))

        (has-permit-rules? rules :create)
        (assoc create-permission (permission-attr entity-key :create))))))

(defn derive-relationship-options
  "Given a relationship attribute, derive pa/* options.

   Determines whether to use inherit-permission or item-permission
   based on target entity's rules.

   - Simple rules (same-org only) → inherit-permission (efficient)
   - Per-item rules (is, member-of, when) → item-permission"
  [rel-attribute target-attribute]
  (let [source-key (entity-namespace (::attr/qualified-key rel-attribute))
        target-key (entity-namespace (::attr/qualified-key target-attribute))
        target-rules (get target-attribute ax/access)]
    (when (seq target-rules)
      (if (requires-per-item-check? target-rules :read)
        ;; Per-item: each child needs individual permission check
        {item-permission (permission-attr target-key :read)}
        ;; Inherit: all children get parent's permission
        {inherit-permission (permission-attr source-key :read target-key)}))))

;; =============================================================================
;; Inline Permission Computation
;; =============================================================================

(defn compute-permissions
  "Compute permissions for an entity. Called by pg2 inline.

   Arguments:
   - user: User map {:id :role :organization :teams}
   - entity: Entity data with all required attrs for rule evaluation
   - rules: ax/access rules
   - org-path: ax/organization path
   - ops: Set of ops to compute (excludes inherited)

   Returns:
   {:can-read? true/false
    :can-write? true/false
    :can-delete? true/false}

   Example:
   (compute-permissions
     {:id user-1 :role :member :organization org-1 :teams #{}}
     {:group/id group-1 :group/organization org-1}
     [{:role :member :same-org true :ops #{:read}}]
     [:group/organization]
     #{:read :write :delete})
   => {:can-read? true :can-write? false :can-delete? false}"
  [user entity rules org-path ops]
  (into {}
        (map (fn [op]
               [(keyword (str "can-" (name op) "?"))
                (axiom-access/allowed? user entity op rules org-path)]))
        ops))

(defn derive-resolver-config
  "Derive resolver configuration from attribute's axiom rules.

   Analyzes ax/access and ax/organization to determine:
   - What Pathom inputs are needed for permission computation
   - What permission attrs to output
   - Which ops inherit from parent vs need computation
   - What related entity data needs batch-fetching

   Arguments:
   - attribute: Attribute map with ax/access, ax/organization

   Returns pa/* options to merge into attribute:
   {::resolver-inputs [...]
    ::permission-outputs [...]
    ::inherited-ops {...}
    ::computed-ops #{...}
    ::related-attrs {...}
    ::virtual? false}

   Returns nil if attribute has no ax/access rules."
  [attribute]
  (let [rules (get attribute ax/access)
        org-path (get attribute ax/organization)
        id-attr (::attr/qualified-key attribute)
        entity-ns (namespace id-attr)]
    (when (seq rules)
      (let [;; Analyze inputs for related entity data
            input-analysis (analysis/analyze-inputs id-attr rules org-path)

            ;; Build Pathom input from analysis
            pathom-input (analysis/build-pathom-input id-attr input-analysis)

            ;; Get inherited operations
            inherited (analysis/inherited-operations rules)

            ;; Collect all ops from rules
            all-ops (into #{} (mapcat (comp extract-ops :ops)) rules)

            ;; Computed ops = all ops minus inherited
            computed (set/difference all-ops (set (keys inherited)))

            ;; Build permission output attrs for all ops
            perm-outputs (mapv #(keyword entity-ns (str "can-" (name %) "?"))
                               all-ops)

            ;; Related attrs that need batch-fetching (from analysis)
            related (:related-attrs input-analysis)

            ;; Check if virtual (no database table)
            ;; This uses rad.pg2/table which may not be present
            is-virtual? (nil? (get attribute :com.fulcrologic.rad.database-adapters.pg2/table))]

        (cond-> {::resolver-inputs pathom-input
                 ::permission-outputs perm-outputs
                 ::inherited-ops inherited
                 ::computed-ops computed
                 ::virtual? is-virtual?}
          (seq related) (assoc ::related-attrs related))))))

(defn derive-inline-options
  "Derive inline permission options for an identity attribute.

   Combines legacy derive-options (for backwards compatibility)
   with new derive-resolver-config (for inline permissions).

   Returns merged pa/* options."
  [attribute]
  (let [legacy (derive-options attribute)
        inline (derive-resolver-config attribute)]
    (merge legacy inline)))

;; =============================================================================
;; Augmentation Functions
;; =============================================================================

(defn augment-attribute
  "Add pa/* options to a single attribute based on ax/* rules.

   For identity attributes: derives entity permissions AND inline permission config
   For ref attributes: derives relationship permissions (needs target lookup)"
  ([attribute]
   (augment-attribute attribute nil))
  ([attribute target-attribute]
   (cond
     ;; Identity attribute - derive entity permissions + inline config
     (::attr/identity? attribute)
     (merge attribute (derive-inline-options attribute))

     ;; Ref attribute with target - derive relationship permissions
     (and (::attr/target attribute) target-attribute)
     (merge attribute (derive-relationship-options attribute target-attribute))

     ;; No derivation needed
     :else attribute)))

(defn augment-attributes
  "Augment a collection of attributes with derived pa/* options.

   Automatically derives:
   - Entity permissions from ax/access on identity attributes
   - Relationship permissions from target's ax/access on ref attributes"
  [attributes]
  (let [k->attr (into {} (map (juxt ::attr/qualified-key identity)) attributes)]
    (mapv (fn [attr]
            (if-let [target-key (::attr/target attr)]
              (augment-attribute attr (get k->attr target-key))
              (augment-attribute attr)))
          attributes)))

;; =============================================================================
;; Query Helpers
;; =============================================================================

(defn permission-attrs-for-entity
  "Returns all permission attribute keywords needed for an entity.

   (permission-attrs-for-entity :issue)
   => [:issue/can-read? :issue/can-write? :issue/can-delete?]"
  [entity-key]
  (filterv some?
           [(permission-attr entity-key :read)
            (permission-attr entity-key :write)
            (permission-attr entity-key :delete)]))

(defn entity-permission-attr
  "Get the entity-permission attribute from an attribute map."
  [attribute]
  (get attribute entity-permission))

(defn inherit-permission-attr
  "Get the inherit-permission attribute from an attribute map."
  [attribute]
  (get attribute inherit-permission))

(defn item-permission-attr
  "Get the item-permission attribute from an attribute map."
  [attribute]
  (get attribute item-permission))

;; =============================================================================
;; Validation
;; =============================================================================

(defn valid-entity-options?
  "Validate entity permission options."
  [options]
  (m/validate EntityPermissionOptions options))

(defn valid-relationship-options?
  "Validate relationship permission options."
  [options]
  (m/validate RelationshipPermissionOptions options))

(defn explain-entity-options
  "Explain validation errors for entity options."
  [options]
  (m/explain EntityPermissionOptions options))

(defn explain-relationship-options
  "Explain validation errors for relationship options."
  [options]
  (m/explain RelationshipPermissionOptions options))

;; =============================================================================
;; Legacy API (Backwards Compatibility)
;; =============================================================================
;; The following provides backwards compatibility with the query-based
;; authorization system. New code should use ax/access rules with
;; augment-attributes instead.

(def auth
  "LEGACY: Query-based authorization attribute.

   Specifies authorization attributes that must be queried and checked.
   New code should use ax/access rules which are automatically converted
   to permission attributes via augment-attributes.

   Example (legacy):
     (defattr id :subject/id :uuid
       {pa/auth [:course/authorized?]})

   Example (new approach):
     (defattr id :group/id :uuid
       {ax/access [{:role :member :same-org true :ops #{:read}}]})"
  ::auth)

(def authorization
  "LEGACY: Authorization key for pathom env."
  ::authorization)

(def authz
  "LEGACY: Per-attribute authorization checks."
  ::authz)

(def restricted
  "LEGACY: Restricted attributes flag."
  ::restricted)

(def bypass?
  "Flag to bypass authorization checks.

   Set in env to skip permission checking (e.g., for system operations)."
  ::bypass?)

(defn auth-attributes
  "LEGACY: Build a map of qualified-key to auth requirements.

   Used by the old query-based authorization system."
  [attributes]
  (let [k->attr (into {} (map (juxt ::attr/qualified-key identity)) attributes)]
    (reduce
     (fn [auth-attrs {::attr/keys [qualified-key identity? identities]
                      ::keys [auth] :as _attribute}]
       (assoc auth-attrs qualified-key
              (if identity?
                auth
                (vec (mapcat (fn [entity-id]
                               (::auth (k->attr entity-id)))
                             identities)))))
     {}
     attributes)))

(defn- children-auth-attributes
  "LEGACY: Get auth attributes for children of an AST node."
  [auth-attrs children]
  (reduce (fn [acc {:keys [dispatch-key]}]
            (into acc (get auth-attrs dispatch-key)))
          #{}
          children))

(defn auth-query
  "LEGACY: Add authorization attributes to query.

   Transforms an EQL query to include authorization checks
   based on the auth-attrs mapping."
  [auth-attrs query]
  (let [ast (eql/query->ast query)
        authed-query
        (-> (eql/transduce-children
             (map (fn [{:keys [children] :as ast-node}]
                    (reduce (fn [acc authorization]
                              (update acc
                                      :children conj
                                      {:type :prop
                                       :dispatch-key authorization
                                       :key authorization}))
                            ast-node
                            (children-auth-attributes auth-attrs children))))
             ast)
            eql/ast->query)]
    (log/debug :authed-query (pr-str authed-query))
    (eql/query->ast authed-query)))
