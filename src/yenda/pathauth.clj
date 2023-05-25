(ns yenda.pathauth
  (:require [com.wsscode.pathom3.connect.operation :as pco]
            [com.wsscode.pathom3.format.shape-descriptor :as pfsd]
            [edn-query-language.core :as eql]
            [clojure.set :as set]
            [taoensso.timbre :as log]))

(def auth ::auth)

(defn auth-attributes [attributes schema]
  (let [k->attr (taoensso.encore/keys-by :com.fulcrologic.rad.attributes/qualified-key attributes)]
    (->> attributes
         (filter #(= schema (:com.fulcrologic.rad.attributes/schema %)))
         (reduce
          (fn [acc attribute]
            (assoc acc (:com.fulcrologic.rad.attributes/qualified-key attribute)
                   (if (:com.fulcrologic.rad.attributes/identity? attribute)
                     (::auth attribute)
                     (vec (mapcat (fn [entity-id]
                                    (::auth (k->attr entity-id)))
                                  (:com.fulcrologic.rad.attributes/identities attribute))))))))))


(defn safe-query
  "remove the pending-authorization keys from the query"
  [query]
  (let [ast (eql/query->ast query)]
    (eql/transduce-children (map (fn [k]
                                   (when (= "pending-authorization" (namespace (:dispatch-key k)))
                                     (throw (Exception. "Illegal query")))
                                   k))
                            ast)))


(defn auth-query
  "remove the pending-authorization keys from the query"
  [auth-attributes query]
  (let [ast (eql/query->ast query)
        authed-query (-> (eql/transduce-children (map (fn [k]
                                                        (if-let [authorizations (some #(get auth-attributes (:dispatch-key %)) (:children k))]
                                                          (reduce (fn [acc authorization]
                                                                    (update acc :children conj {:type :prop :dispatch-key authorization :key authorization}))
                                                                  k
                                                                  authorizations)
                                                          k)))
                                                 ast)
                         eql/ast->query)]
    (log/debug :authed-query (pr-str authed-query))
    (eql/query->ast authed-query)))
