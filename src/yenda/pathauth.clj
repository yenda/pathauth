(ns yenda.pathauth
  (:require [com.wsscode.pathom3.connect.operation :as pco]
            [com.wsscode.pathom3.format.shape-descriptor :as pfsd]
            [edn-query-language.core :as eql]
            [clojure.set :as set]
            [taoensso.timbre :as log]))

(def auth ::auth)

(defn circular-dependency? [resolver]
  (-> resolver :config ::circular?))

(defn wrap-authorization [resolver]
  (if-let [authorizations (-> resolver :config ::auth)]
    (if-not (circular-dependency? resolver)
      ;; simple resolver
      (let [input (get-in resolver [:config ::pco/input])
            new-input (-> input (concat authorizations) vec)
            new-requires (pco/describe-input new-input)]
        (-> resolver
            (assoc-in [:config ::pco/input] new-input)
            (update :config merge  new-requires)))

      ;; special resolver
      (let [{:keys [resolve config]} resolver
            {::pco/keys [input output op-name batch?]} config
            pending-resolver-op-name (symbol
                                      "pending-authorization"
                                      (str (namespace op-name) "--" (name op-name)))
            pending-key (keyword pending-resolver-op-name)]
        [(pco/resolver
          {::pco/op-name op-name
           ;; TODO: optimize to only ouput the inputs that are required by the
           ;; pending resolver
           ::pco/output [{pending-key (vec (into #{} (concat input output)))}]
           ::pco/input input
           ::pco/batch? batch?
           ::pco/resolve (fn [env inputs]
                           (log/info :batch? op-name batch?)
                           (time (if batch?
                                   (mapv (fn [result input]
                                           {pending-key (merge input result)})
                                         (resolve env inputs)
                                         inputs)
                                   {pending-key (merge inputs (resolve env inputs))})))})
         (pco/resolver
          {::pco/op-name pending-resolver-op-name
           ::pco/output  output
           #_#_           ::pco/batch?  true
           ::pco/resolve
           (fn [env inputs]
             (get inputs pending-key))
           #_(fn [env inputs]
               (log/info :batch? pending-resolver-op-name)
               (mapv (fn [input] ) inputs))
           ::pco/input [{pending-key (vec (into #{} (concat input output authorizations)))}]})]))

    ;; resolver without authorization or authorization resolver
    resolver))

(defn auth-setup [operation-or-operations]
  ;; TODO: automatically detect circular dependencies between authorization resolvers
  ;; and resolvers
  #_(let [auth-attributes (reduce (fn [acc {:keys [config]}]
                                    (if-let [authorizations (::auth config)]
                                      (set/union acc (into #{} authorizations))
                                      acc))
                                  #{}
                                  resolvers)])
  (mapv (fn [operation-or-operations]
          (if (sequential? operation-or-operations)
            (auth-setup operation-or-operations)
            (wrap-authorization operation-or-operations)))
        operation-or-operations))

(defn safe-query
  "remove the pending-authorization keys from the query"
  [query]
  (let [ast (eql/query->ast query)]
    (eql/transduce-children (map (fn [k]
                                   (when (= "pending-authorization" (namespace (:dispatch-key k)))
                                     (throw (Exception. "Illegal query")))
                                   k))
                            ast)))
