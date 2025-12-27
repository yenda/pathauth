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
  (testing "derives read permission from rules"
    (let [attr {::attr/qualified-key :issue/id
                ::attr/identity? true
                ax/access [{:role :member :same-org true :ops #{:read}}]}
          result (pa/derive-options attr)]
      (is (= :issue/can-read? (pa/entity-permission result)))
      (is (nil? (pa/write-permission result)))
      (is (nil? (pa/delete-permission result)))))

  (testing "derives multiple permissions from rules"
    (let [attr {::attr/qualified-key :issue/id
                ::attr/identity? true
                ax/access [{:role :member :same-org true :ops #{:read}}
                           {:is :issue/reporter :ops #{:read :write}}
                           {:role :admin :same-org true :ops #{:read :write :delete}}]}
          result (pa/derive-options attr)]
      (is (= :issue/can-read? (pa/entity-permission result)))
      (is (= :issue/can-write? (pa/write-permission result)))
      (is (= :issue/can-delete? (pa/delete-permission result)))))

  (testing "returns nil for attributes without rules"
    (let [attr {::attr/qualified-key :issue/id
                ::attr/identity? true}]
      (is (nil? (pa/derive-options attr)))))

  (testing "ignores forbid-only rules"
    (let [attr {::attr/qualified-key :issue/id
                ::attr/identity? true
                ax/access [{:forbid true :when [:issue/locked] :ops #{:write}}]}
          result (pa/derive-options attr)]
      ;; No permit rules, so no permissions derived
      (is (nil? (pa/entity-permission result))))))

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
      (is (= :issue/can-read? (pa/item-permission result))))))

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
      (is (= :issue/can-read? (pa/item-permission rel-attr))))))

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

(deftest validation-test
  (testing "valid entity options pass validation"
    (is (pa/valid-entity-options?
         {::pa/entity-permission :issue/can-read?
          ::pa/write-permission :issue/can-write?})))

  (testing "invalid permission attr fails validation"
    (is (not (pa/valid-entity-options?
              {::pa/entity-permission :issue/read})))) ;; missing ?

  (testing "valid relationship options pass validation"
    (is (pa/valid-relationship-options?
         {::pa/inherit-permission :project/can-read-issues?}))
    (is (pa/valid-relationship-options?
         {::pa/item-permission :issue/can-read?}))))
