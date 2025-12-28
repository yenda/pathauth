(ns yenda.pathauth
  "Pathauth bridges axiom's authorization rules (ax/*) to pg2's resolver generation.

   Transforms declarative access rules into resolver input requirements (pa/* options).
   pg2 reads these options to generate gated resolvers.

   ## Architecture

   ```
   Axiom (ax/access rules)
       ↓
   Pathauth (derives pa/* options)
       ↓
   pg2 (reads pa/*, generates gated resolvers)
   ```

   ## Usage

   ```clojure
   (defattr issue-id :issue/id :uuid
     {::attr/identity? true
      ax/access [{:role :member :same-org true :ops #{:read}}]

      ;; Pathauth options (derived or explicit)
      pa/entity-permission :issue/can-read?})
   ```"
  (:require
   [com.fulcrologic.rad.attributes :as-alias attr]
   [axiom :as ax]
   [malli.core :as m]))

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

(defn augment-attribute
  "Add pa/* options to a single attribute based on ax/* rules.

   For identity attributes: derives entity permissions
   For ref attributes: derives relationship permissions (needs target lookup)"
  ([attribute]
   (augment-attribute attribute nil))
  ([attribute target-attribute]
   (cond
     ;; Identity attribute - derive entity permissions
     (::attr/identity? attribute)
     (merge attribute (derive-options attribute))

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
