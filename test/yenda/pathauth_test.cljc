(ns yenda.pathauth-test
  (:require
   [clojure.test :refer [deftest testing is]]
   [yenda.pathauth :as pa]
   [com.fulcrologic.rad.attributes :as-alias attr]
   [axiom :as ax]))

;; =============================================================================
;; Permission Attribute Naming Tests
;; =============================================================================

(deftest permission-attr-test
  (testing "generates entity permission attr"
    (is (= :issue/can-read? (pa/permission-attr :issue :read)))
    (is (= :issue/can-write? (pa/permission-attr :issue :write)))
    (is (= :issue/can-delete? (pa/permission-attr :issue :delete))))

  (testing "generates relationship permission attr"
    (is (= :project/can-read-issues? (pa/permission-attr :project :read :issues)))
    (is (= :project/can-create-issue? (pa/permission-attr :project :create :issue)))))

(deftest entity-namespace-test
  (testing "extracts namespace as keyword"
    (is (= :issue (pa/entity-namespace :issue/id)))
    (is (= :project (pa/entity-namespace :project/issues)))))

;; =============================================================================
;; Derive Options Tests
;; =============================================================================

(deftest derive-options-test
  (testing "read-only rules"
    (testing "returns only entity-permission"
      (let [attr {::attr/qualified-key :issue/id
                  ax/access [{:role :member :same-org true :ops #{:read}}]}
            result (pa/derive-options attr)]
        (is (= :issue/can-read? (pa/entity-permission result)))
        (is (nil? (pa/write-permission result)))
        (is (nil? (pa/delete-permission result)))
        (is (nil? (pa/create-permission result))))))

  (testing "read + write rules"
    (testing "returns entity-permission and write-permission"
      (let [attr {::attr/qualified-key :issue/id
                  ax/access [{:role :member :same-org true :ops #{:read :write}}]}
            result (pa/derive-options attr)]
        (is (= :issue/can-read? (pa/entity-permission result)))
        (is (= :issue/can-write? (pa/write-permission result)))
        (is (nil? (pa/delete-permission result)))
        (is (nil? (pa/create-permission result))))))

  (testing "all CRUD operations"
    (testing "returns all four permission types"
      (let [attr {::attr/qualified-key :issue/id
                  ax/access [{:role :admin :same-org true :ops #{:read :write :delete :create}}]}
            result (pa/derive-options attr)]
        (is (= :issue/can-read? (pa/entity-permission result)))
        (is (= :issue/can-write? (pa/write-permission result)))
        (is (= :issue/can-delete? (pa/delete-permission result)))
        (is (= :issue/can-create? (pa/create-permission result))))))

  (testing "no rules"
    (testing "nil access returns nil"
      (let [attr {::attr/qualified-key :issue/id}]
        (is (nil? (pa/derive-options attr)))))
    (testing "empty access vector returns nil"
      (let [attr {::attr/qualified-key :issue/id
                  ax/access []}]
        (is (nil? (pa/derive-options attr))))))

  (testing "forbid-only rules"
    (testing "no permission attr for ops that only have forbid rules"
      (let [attr {::attr/qualified-key :issue/id
                  ax/access [{:forbid true :when [:issue/locked] :ops #{:write}}]}
            result (pa/derive-options attr)]
        ;; Returns empty map - rules exist but none are permit rules
        (is (= {} result))
        (is (nil? (pa/entity-permission result)))
        (is (nil? (pa/write-permission result))))))

  (testing "mixed permit + forbid"
    (testing "only generates for ops with permit rules"
      (let [attr {::attr/qualified-key :issue/id
                  ax/access [{:role :member :same-org true :ops #{:read}}
                             {:forbid true :when [:issue/locked] :ops #{:write :delete}}]}
            result (pa/derive-options attr)]
        (is (= :issue/can-read? (pa/entity-permission result)))
        (is (nil? (pa/write-permission result)))
        (is (nil? (pa/delete-permission result))))))

  (testing "multiple rules for same op"
    (testing "generates permission when any rule permits"
      (let [attr {::attr/qualified-key :issue/id
                  ax/access [{:role :member :same-org true :ops #{:read}}
                             {:is :issue/reporter :ops #{:read :write}}
                             {:role :admin :same-org true :ops #{:read :write :delete}}]}
            result (pa/derive-options attr)]
        (is (= :issue/can-read? (pa/entity-permission result)))
        (is (= :issue/can-write? (pa/write-permission result)))
        (is (= :issue/can-delete? (pa/delete-permission result)))))))

;; =============================================================================
;; Derive Relationship Options Tests
;; =============================================================================

(deftest derive-relationship-options-test
  (testing "uses inherit-permission for simple same-org rules"
    (let [rel-attr {::attr/qualified-key :project/issues
                    ::attr/target :issue/id}
          target-attr {::attr/qualified-key :issue/id
                       ::attr/identity? true
                       ax/access [{:role :member :same-org true :ops #{:read}}]}
          result (pa/derive-relationship-options rel-attr target-attr)]
      (is (= :project/can-read-issue? (pa/inherit-permission result)))
      (is (nil? (pa/item-permission result)))))

  (testing "uses item-permission for per-item rules with :is"
    (let [rel-attr {::attr/qualified-key :project/issues
                    ::attr/target :issue/id}
          target-attr {::attr/qualified-key :issue/id
                       ::attr/identity? true
                       ax/access [{:is :issue/reporter :ops #{:read}}]}
          result (pa/derive-relationship-options rel-attr target-attr)]
      (is (nil? (pa/inherit-permission result)))
      (is (= :issue/can-read? (pa/item-permission result)))))

  (testing "uses item-permission for rules with :when"
    (let [rel-attr {::attr/qualified-key :project/issues
                    ::attr/target :issue/id}
          target-attr {::attr/qualified-key :issue/id
                       ::attr/identity? true
                       ax/access [{:role :member :same-org true
                                   :when [:issue/public] :ops #{:read}}]}
          result (pa/derive-relationship-options rel-attr target-attr)]
      (is (nil? (pa/inherit-permission result)))
      (is (= :issue/can-read? (pa/item-permission result)))))

  (testing "uses item-permission for rules with :member-of"
    (let [rel-attr {::attr/qualified-key :project/issues
                    ::attr/target :issue/id}
          target-attr {::attr/qualified-key :issue/id
                       ::attr/identity? true
                       ax/access [{:member-of :issue/team :ops #{:read}}]}
          result (pa/derive-relationship-options rel-attr target-attr)]
      (is (= :issue/can-read? (pa/item-permission result)))))

  (testing "uses item-permission for rules with :inherit-from"
    (let [rel-attr {::attr/qualified-key :project/issues
                    ::attr/target :issue/id}
          target-attr {::attr/qualified-key :issue/id
                       ::attr/identity? true
                       ax/access [{:inherit-from :issue/parent :ops #{:read}}]}
          result (pa/derive-relationship-options rel-attr target-attr)]
      (is (nil? (pa/inherit-permission result)))
      (is (= :issue/can-read? (pa/item-permission result)))))

  (testing "returns nil when target has no access rules"
    (let [rel-attr {::attr/qualified-key :project/issues
                    ::attr/target :issue/id}
          target-attr {::attr/qualified-key :issue/id
                       ::attr/identity? true}]
      (is (nil? (pa/derive-relationship-options rel-attr target-attr))))))

;; =============================================================================
;; Augment Attributes Tests
;; =============================================================================

(deftest augment-attribute-test
  (testing "augments identity attribute with entity permissions"
    (let [attr {::attr/qualified-key :issue/id
                ::attr/identity? true
                ax/access [{:role :member :same-org true :ops #{:read :write}}]}
          result (pa/augment-attribute attr)]
      (is (= :issue/can-read? (pa/entity-permission result)))
      (is (= :issue/can-write? (pa/write-permission result)))))

  (testing "augments ref attribute with relationship permissions"
    (let [rel-attr {::attr/qualified-key :project/issues
                    ::attr/target :issue/id}
          target-attr {::attr/qualified-key :issue/id
                       ::attr/identity? true
                       ax/access [{:role :member :same-org true :ops #{:read}}]}
          result (pa/augment-attribute rel-attr target-attr)]
      (is (= :project/can-read-issue? (pa/inherit-permission result)))))

  (testing "preserves existing attribute keys"
    (let [attr {::attr/qualified-key :issue/id
                ::attr/identity? true
                :custom/key "preserved"
                ax/access [{:role :member :ops #{:read}}]}
          result (pa/augment-attribute attr)]
      (is (= "preserved" (:custom/key result)))
      (is (= :issue/can-read? (pa/entity-permission result))))))

(deftest augment-attributes-test
  (testing "augments collection with inherit-permission for simple rules"
    (let [attrs [{::attr/qualified-key :project/id
                  ::attr/identity? true
                  ax/access [{:role :member :same-org true :ops #{:read}}]}
                 {::attr/qualified-key :issue/id
                  ::attr/identity? true
                  ;; Only :same-org for read -> inherit-permission
                  ax/access [{:role :member :same-org true :ops #{:read}}
                             {:is :issue/reporter :ops #{:write}}]}
                 {::attr/qualified-key :project/issues
                  ::attr/target :issue/id
                  ::attr/cardinality :many}]
          result (pa/augment-attributes attrs)
          project-attr (first result)
          issue-attr (second result)
          rel-attr (nth result 2)]
      ;; Project entity permissions
      (is (= :project/can-read? (pa/entity-permission project-attr)))
      ;; Issue entity permissions
      (is (= :issue/can-read? (pa/entity-permission issue-attr)))
      (is (= :issue/can-write? (pa/write-permission issue-attr)))
      ;; Relationship uses inherit-permission because issue read is same-org only
      (is (= :project/can-read-issue? (pa/inherit-permission rel-attr)))))

  (testing "augments collection with item-permission for per-item rules"
    (let [attrs [{::attr/qualified-key :project/id
                  ::attr/identity? true
                  ax/access [{:role :member :same-org true :ops #{:read}}]}
                 {::attr/qualified-key :issue/id
                  ::attr/identity? true
                  ;; :is rule for read -> item-permission
                  ax/access [{:is :issue/reporter :ops #{:read}}]}
                 {::attr/qualified-key :project/issues
                  ::attr/target :issue/id
                  ::attr/cardinality :many}]
          result (pa/augment-attributes attrs)
          rel-attr (nth result 2)]
      ;; Relationship uses item-permission because issue read requires per-item check
      (is (= :issue/can-read? (pa/item-permission rel-attr)))))

  (testing "attribute without ax/access"
    (testing "is unchanged"
      (let [attrs [{::attr/qualified-key :issue/title
                    ::attr/type :string
                    :custom/key "value"}]
            result (pa/augment-attributes attrs)
            attr (first result)]
        ;; No pa/* keys added
        (is (nil? (pa/entity-permission attr)))
        (is (nil? (pa/write-permission attr)))
        (is (nil? (pa/inherit-permission attr)))
        (is (nil? (pa/item-permission attr)))
        ;; Original keys preserved
        (is (= :issue/title (::attr/qualified-key attr)))
        (is (= :string (::attr/type attr)))
        (is (= "value" (:custom/key attr))))))

  (testing "preserves existing attributes"
    (testing "during augmentation"
      (let [attrs [{::attr/qualified-key :issue/id
                    ::attr/identity? true
                    ::attr/type :uuid
                    :custom/key "preserved"
                    :another/key 42
                    ax/access [{:role :member :ops #{:read :write}}]}]
            result (pa/augment-attributes attrs)
            attr (first result)]
        ;; Original keys preserved
        (is (= :issue/id (::attr/qualified-key attr)))
        (is (= true (::attr/identity? attr)))
        (is (= :uuid (::attr/type attr)))
        (is (= "preserved" (:custom/key attr)))
        (is (= 42 (:another/key attr)))
        ;; pa/* keys added via augmentation
        (is (= :issue/can-read? (pa/entity-permission attr)))
        (is (= :issue/can-write? (pa/write-permission attr)))
        ;; ax/access still present
        (is (seq (get attr ax/access))))))

  (testing "mixed collection"
    (testing "only relevant attrs get permissions"
      (let [attrs [{::attr/qualified-key :project/id
                    ::attr/identity? true
                    ax/access [{:role :member :same-org true :ops #{:read}}]}
                   ;; Plain attribute - no ax/access
                   {::attr/qualified-key :project/name
                    ::attr/type :string}
                   {::attr/qualified-key :issue/id
                    ::attr/identity? true
                    ax/access [{:role :member :same-org true :ops #{:read :write}}]}
                   ;; Ref attribute
                   {::attr/qualified-key :project/issues
                    ::attr/target :issue/id
                    ::attr/cardinality :many}
                   ;; Another plain attribute
                   {::attr/qualified-key :issue/title
                    ::attr/type :string}]
            result (pa/augment-attributes attrs)
            project-id (nth result 0)
            project-name (nth result 1)
            issue-id (nth result 2)
            project-issues (nth result 3)
            issue-title (nth result 4)]
        ;; Identity attrs get entity permissions
        (is (= :project/can-read? (pa/entity-permission project-id)))
        (is (= :issue/can-read? (pa/entity-permission issue-id)))
        (is (= :issue/can-write? (pa/write-permission issue-id)))
        ;; Plain attrs unchanged
        (is (nil? (pa/entity-permission project-name)))
        (is (nil? (pa/entity-permission issue-title)))
        ;; Ref attr gets relationship permission
        (is (= :project/can-read-issue? (pa/inherit-permission project-issues)))))))

;; =============================================================================
;; Helper Function Tests
;; =============================================================================

(deftest permission-attrs-for-entity-test
  (testing "returns all permission attrs for entity"
    (is (= [:issue/can-read? :issue/can-write? :issue/can-delete?]
           (pa/permission-attrs-for-entity :issue)))))

;; =============================================================================
;; Validation Tests
;; =============================================================================

(deftest valid-entity-options-test
  (testing "valid entity options"
    (testing "single permission key"
      (is (true? (pa/valid-entity-options?
                  {::pa/entity-permission :issue/can-read?}))))
    (testing "multiple permission keys"
      (is (true? (pa/valid-entity-options?
                  {::pa/entity-permission :issue/can-read?
                   ::pa/write-permission :issue/can-write?
                   ::pa/delete-permission :issue/can-delete?
                   ::pa/create-permission :issue/can-create?}))))
    (testing "empty map (all keys optional)"
      (is (true? (pa/valid-entity-options? {})))))

  (testing "invalid entity options"
    (testing "keyword doesn't end with ?"
      (is (false? (pa/valid-entity-options?
                   {::pa/entity-permission :issue/can-read}))))
    (testing "value is not a keyword"
      (is (false? (pa/valid-entity-options?
                   {::pa/entity-permission "issue/can-read?"})))
      (is (false? (pa/valid-entity-options?
                   {::pa/entity-permission 123})))
      (is (false? (pa/valid-entity-options?
                   {::pa/entity-permission nil}))))))

(deftest valid-relationship-options-test
  (testing "valid relationship options"
    (testing "inherit-permission"
      (is (true? (pa/valid-relationship-options?
                  {::pa/inherit-permission :project/can-read-issues?}))))
    (testing "item-permission"
      (is (true? (pa/valid-relationship-options?
                  {::pa/item-permission :issue/can-read?}))))
    (testing "empty map (all keys optional)"
      (is (true? (pa/valid-relationship-options? {})))))

  (testing "invalid relationship options"
    (testing "inherit-permission doesn't end with ?"
      (is (false? (pa/valid-relationship-options?
                   {::pa/inherit-permission :project/can-read-issues}))))
    (testing "item-permission doesn't end with ?"
      (is (false? (pa/valid-relationship-options?
                   {::pa/item-permission :issue/can-read}))))
    (testing "value is not a keyword"
      (is (false? (pa/valid-relationship-options?
                   {::pa/inherit-permission "project/can-read-issues?"}))))))

(deftest explain-entity-options-test
  (testing "returns nil for valid options"
    (is (nil? (pa/explain-entity-options
               {::pa/entity-permission :issue/can-read?})))
    (is (nil? (pa/explain-entity-options {}))))

  (testing "returns explanation for invalid options"
    (let [explanation (pa/explain-entity-options
                       {::pa/entity-permission :issue/can-read})]
      (is (some? explanation))
      (is (contains? explanation :errors)))))

(deftest explain-relationship-options-test
  (testing "returns nil for valid options"
    (is (nil? (pa/explain-relationship-options
               {::pa/inherit-permission :project/can-read-issues?})))
    (is (nil? (pa/explain-relationship-options
               {::pa/item-permission :issue/can-read?})))
    (is (nil? (pa/explain-relationship-options {}))))

  (testing "returns explanation for invalid options"
    (let [explanation (pa/explain-relationship-options
                       {::pa/inherit-permission :project/can-read-issues})]
      (is (some? explanation))
      (is (contains? explanation :errors)))))
