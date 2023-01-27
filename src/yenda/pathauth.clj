(ns yenda.pathauth
  (:require [com.wsscode.pathom3.connect.operation :as pco]))

(defn circular-dependency? [resolver]
  true)

(defn wrap-authorization [resolver]
  (if-let [authorizations (:authorization resolver)]
    (if-not (circular-dependency? resolver)
      ;; simple resolver
      (update resolver ::pco/input concat authorizations)

      ;; special resolver
      (let [{::pco/keys [input output op-name]
             ::keys [authorizations]} resolver
            pending-resolver-op-name (symbol
                                      "pending-authorization"
                                      (str (namespace op-name) "--" (name op-name)))
            pending-key (keyword pending-resolver-op-name)]
        [resolver
         (pco/resolver
          (cond-> {::pco/op-name pending-resolver-op-name
                   ::pco/output  output
                   ::pco/batch?  true
                   ::pco/resolve (fn [env inputs]
                                   (mapv pending-key inputs))
                   ::pco/input [{pending-key (concat output authorizations)}]}))]))

    ;; resolver without authorization or authorization resolver
    resolver))
