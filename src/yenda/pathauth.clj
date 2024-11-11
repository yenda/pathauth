(ns yenda.pathauth
  (:require
   [com.fulcrologic.rad.attributes :as-alias attr]
   [edn-query-language.core :as eql]
   [taoensso.timbre :as log]))

(def auth ::auth)
(def restricted ::restricted)

(defn auth-attributes [attributes schema]
  (let [k->attr (taoensso.encore/keys-by ::attr/qualified-key attributes)]
    (->> attributes
         ;; are we sure we even want to filter by schema here?
         #_(filter #(= schema (::attr/schema %)))
         (reduce
          (fn [auth-attributes {::attr/keys [qualified-key identity? identities]
                                ::keys [auth] :as attribute}]
            (assoc auth-attributes qualified-key
                   (if identity?
                     auth
                     (vec (mapcat (fn [entity-id]
                                    (::auth (k->attr entity-id)))
                                  identities)))))
          {}))))

(defn children-auth-attributes [auth-attrs children]
  (reduce (fn [acc {:keys [dispatch-key]}]
            (into acc (get auth-attrs dispatch-key)))
          #{}
          children))

(defn auth-query
  "remove the pending-authorization keys from the query"
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

