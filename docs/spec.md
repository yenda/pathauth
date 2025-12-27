# Pathauth Spec

**Status:** Draft
**Version:** 2.0.0

## Purpose

Pathauth bridges axiom's authorization rules (`ax/*`) to pg2's resolver generation (`pa/*`). It transforms declarative access rules into resolver input requirements.

## Architecture Position

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│     Axiom       │         │    Pathauth     │         │      pg2        │
│                 │         │                 │         │                 │
│  ax/access      │────────▶│  Reads ax/*     │────────▶│  Reads pa/*     │
│  ax/organization│         │  Generates pa/* │         │  Gates resolvers│
│                 │         │                 │         │                 │
└─────────────────┘         └─────────────────┘         └─────────────────┘
```

**Key constraint:** Pathauth knows about axiom rules. pg2 only knows about `pa/*` options.

## Namespace

```clojure
(ns yenda.pathauth
  (:require
    [com.fulcrologic.rad.attributes :as-alias attr]
    [axiom :as ax]))
```

## Keys (`pa/*`)

### `pa/entity-permission`

**Type:** keyword
**Purpose:** Specifies the boolean permission attribute required to access entity data.

```clojure
pa/entity-permission :issue/can-read?
```

**Effect on pg2:** Generated entity resolver will have this attribute in `::pco/input`. Resolver only fetches data when value is `true`.

```clojure
;; pg2 generates:
{::pco/input [:issue/id :issue/can-read?]
 ::pco/output [:issue/title :issue/description ...]}
```

### `pa/inherit-permission`

**Type:** keyword
**Purpose:** For relationships where all children inherit parent's permission (all-or-nothing).

```clojure
(defattr project-issues :project/issues :ref
  {::attr/target :issue/id
   pa/inherit-permission :project/can-read-issues?})
```

**Effect on pg2:** Relationship resolver gates on parent permission. When permitted, all children receive `true` for their entity permission.

```clojure
;; pg2 generates:
{::pco/input [:project/id :project/can-read-issues?]
 ::pco/output [{:project/issues [:issue/id :issue/can-read?]}]}

;; Resolver behavior:
(when can-read-issues?
  {:project/issues
   (mapv #(assoc % :issue/can-read? true) (fetch-issues id))})
```

### `pa/item-permission`

**Type:** keyword
**Purpose:** For relationships where each child has individual permission check.

```clojure
(defattr project-issues :project/issues :ref
  {::attr/target :issue/id
   pa/item-permission :issue/can-read?})
```

**Effect on pg2:** Relationship resolver returns all child IDs. Permission is computed per-item by axiom's permission resolver. Entity data only fetched for authorized items.

```clojure
;; pg2 generates:
{::pco/input [:project/id]
 ::pco/output [{:project/issues [:issue/id]}]}

;; Returns all IDs, axiom computes :issue/can-read? per item
;; pg2's entity resolver gates on :issue/can-read?
```

### `pa/create-permission`

**Type:** keyword
**Purpose:** Permission to create children under this entity.

```clojure
pa/create-permission :project/can-create-issue?
```

**Effect:** Mutations check this before creating child entities.

### `pa/write-permission`

**Type:** keyword
**Purpose:** Permission to modify entity.

```clojure
pa/write-permission :issue/can-write?
```

**Effect:** Mutations check this before updating entity.

### `pa/delete-permission`

**Type:** keyword
**Purpose:** Permission to delete entity.

```clojure
pa/delete-permission :issue/can-delete?
```

**Effect:** Mutations check this before deleting entity.

## Permission Attribute Naming Convention

```
:<entity>/<can-action>?           ;; Entity-level
:<entity>/<can-action-target>?    ;; Relationship/create
```

| Pattern | Example | Meaning |
|---------|---------|---------|
| `:<entity>/can-read?` | `:issue/can-read?` | Can view entity fields |
| `:<entity>/can-write?` | `:issue/can-write?` | Can modify entity |
| `:<entity>/can-delete?` | `:issue/can-delete?` | Can delete entity |
| `:<entity>/can-read-<rel>?` | `:project/can-read-issues?` | Can traverse relationship |
| `:<entity>/can-create-<child>?` | `:project/can-create-issue?` | Can create child |

## Functions

### `pa/derive-options`

Generates `pa/*` options from `ax/*` rules on an attribute.

```clojure
(defn derive-options
  "Given an attribute with ax/* rules, derive pa/* options."
  [attribute]
  ...)

;; Input:
{::attr/qualified-key :issue/id
 ::attr/identity? true
 ax/access [{:role :member :same-org true :ops #{:read}}
            {:is :issue/reporter :ops #{:read :write :delete}}]}

;; Output:
{pa/entity-permission :issue/can-read?
 pa/write-permission :issue/can-write?
 pa/delete-permission :issue/can-delete?}
```

### `pa/derive-relationship-options`

Generates `pa/*` options for relationship attributes.

```clojure
(defn derive-relationship-options
  "Given a relationship attribute, derive pa/* options."
  [attribute target-attribute]
  ...)

;; Heuristic:
;; - If target has simple rules (same-org) → pa/inherit-permission
;; - If target has per-item rules (is, member-of) → pa/item-permission
```

### `pa/permission-attrs-for-entity`

Returns all permission attribute keywords for an entity type.

```clojure
(defn permission-attrs-for-entity
  "Returns permission attrs needed for entity."
  [entity-key]
  ...)

;; Example:
(permission-attrs-for-entity :issue)
;; => [:issue/can-read? :issue/can-write? :issue/can-delete?]
```

### `pa/augment-attributes`

Augments a collection of attributes with derived `pa/*` options.

```clojure
(defn augment-attributes
  "Add pa/* options to attributes based on ax/* rules."
  [attributes]
  (mapv (fn [attr]
          (if (::attr/identity? attr)
            (merge attr (derive-options attr))
            (if-let [target (::attr/target attr)]
              (merge attr (derive-relationship-options attr (get-attr target)))
              attr)))
        attributes))
```

## Integration with pg2

pg2 reads `pa/*` options during resolver generation:

```clojure
;; In pg2's build-id-resolver-config
(defn build-id-resolver-config [id-attr ...]
  (let [entity-perm (pa/entity-permission id-attr)
        base-input [(::attr/qualified-key id-attr)]
        input (if entity-perm
                (conj base-input entity-perm)
                base-input)]
    {::pco/input input
     ...}))
```

pg2 does NOT:
- Know about `ax/*` rules
- Know how permissions are computed
- Generate permission resolvers

## Integration with Axiom

Axiom generates permission resolvers:

```clojure
;; In axiom.pathom
(defn generate-permission-resolvers
  "Generate Pathom resolvers for permission attributes."
  [entity-type rules]
  [(generate-can-read-resolver entity-type rules)
   (generate-can-write-resolver entity-type rules)
   (generate-can-delete-resolver entity-type rules)])
```

Axiom does NOT:
- Know about pg2
- Know how data is fetched
- Generate data resolvers

## Full Example

### Attribute Definition

```clojure
(defattr issue-id :issue/id :uuid
  {::attr/identity? true
   ::pg2/table "issues"

   ;; Axiom rules
   ax/organization [:issue/project :project/organization]
   ax/access [{:role :member :same-org true :ops #{:read}}
              {:is :issue/reporter :ops #{:read :write}}
              {:role :admin :same-org true :ops #{:read :write :delete}}]

   ;; Pathauth options (can be derived or explicit)
   pa/entity-permission :issue/can-read?
   pa/write-permission :issue/can-write?
   pa/delete-permission :issue/can-delete?})

(defattr project-issues :project/issues :ref
  {::attr/target :issue/id
   ::attr/cardinality :many

   ;; Pathauth - inherit from parent (all issues visible if project is)
   pa/inherit-permission :project/can-read-issues?})
```

### Generated Resolvers

**By Axiom:**
```clojure
;; Permission resolver
(pco/resolver 'issue-can-read
  {::pco/input [:issue/id]
   ::pco/output [:issue/can-read?]
   ::pco/batch? true}
  (fn [env issues]
    (mapv #(hash-map :issue/can-read?
                     (access/allowed? (make-ctx env) % :read rules))
          issues)))
```

**By pg2:**
```clojure
;; Entity resolver (gated)
(pco/resolver 'issue-resolver
  {::pco/input [:issue/id :issue/can-read?]  ;; <-- from pa/entity-permission
   ::pco/output [:issue/title :issue/description ...]
   ::pco/batch? true}
  (fn [env issues]
    (let [authorized (filter :issue/can-read? issues)
          ids (mapv :issue/id authorized)
          results (query-issues ids)]
      ;; Return nil for unauthorized
      (mapv #(when (:issue/can-read? %)
               (get results (:issue/id %)))
            issues))))
```

### Resolution Flow

```
Query: [{[:issue/id 123] [:issue/title]}]

1. pg2's issue-resolver needs :issue/can-read?
2. Pathom calls axiom's issue-can-read resolver
3. axiom computes permission → {:issue/can-read? true}
4. pg2's issue-resolver receives input with can-read? true
5. pg2 fetches and returns data
```

## Migration from v1

### Removed Keys

| v1 Key | Replacement |
|--------|-------------|
| `::auth` | `pa/entity-permission` + axiom rules |
| `::authz` | `pa/entity-permission` |
| `::restricted` | `pa/entity-permission` |
| `::authorization` | Removed (implicit in resolver deps) |

### Removed Functions

| v1 Function | Replacement |
|-------------|-------------|
| `auth-query` | Not needed (Pathom resolves deps) |
| `auth-attributes` | `derive-options` |
| `children-auth-attributes` | Not needed |

### Migration Steps

1. Replace `::auth` with `ax/access` rules on entity attributes
2. Replace `::authz`/`::restricted` with `pa/entity-permission`
3. Remove query manipulation code
4. Add axiom permission resolvers to Pathom env
5. Enable `pa/*` reading in pg2

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | - | Original query manipulation approach |
| 2.0.0 | 2025-12 | Resolver dependency approach |
