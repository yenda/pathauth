(ns yenda.pathauth-test
  (:require [clojure.test :refer :all]
            [yenda.pathauth :refer :all :as pa]
            [com.wsscode.pathom3.format.shape-descriptor :as pfsd]
            [com.wsscode.pathom3.connect.operation :as pco]
            [com.wsscode.pathom3.connect.indexes :as pci]
            [com.wsscode.pathom3.connect.planner :as pcp]
            [edn-query-language.core :as eql]
            [com.wsscode.pathom3.interface.eql :as p.eql]
            [com.wsscode.pathom3.interface.async.eql :as p.a.eql]))

(pco/defresolver toy
  [env input]
  {::pco/input  [:toy/id]
   ::pco/batch? true
   ::pco/output [:toy/name :toy/id :toy/order]}

  (map #(get {1 {:toy/name "Bobby" :toy/id 1 :toy/order 3}
              2 {:toy/name "Alice" :toy/id 2 :toy/order 2}
              3 {:toy/name "Rene" :toy/id 3 :toy/order 1}}
             (:toy/id %))
       input))

(pco/defresolver child-toys
  [env input]
  {::pco/input  [:child/id]
   ::pco/batch? true
   ::pa/auth [:child/parent?]
   ::pco/output [{:child/toys [:toy/id]}]}

  [{:child/toys [{:toy/id 1}
                 {:toy/id 2}
                 {:toy/id 3}]}])

(pco/defresolver favorite-toy
  [env input]
  {::pco/input  [{:child/toys [:toy/id :toy/order]}]
   ::pco/batch? true
   ::pco/output [{:child/favorite-toy [:toy/id]}]}

  [{:child/favorite-toy (->> (:child/toys (first input))
                             (sort-by :toy/order)
                             first)}])

(pco/defresolver child-parents
  [env inputs]
  {::pco/input  [:child/id]
   ::pco/batch? true
   ::pa/auth [:child/parent?]
   ::pa/circular? true
   ::pco/output [:parent/id]}
  (let [parents {1  4
                 2  5
                 3  6}]
    (mapv (fn [input]
            {:parent/id (get parents (:child/id input))})
          inputs)))

(pco/defresolver parent?
  [{:keys [parent-id] :as env} inputs]
  {::pco/input  [:child/id :parent/id]
   ::pco/batch? true
   ::pco/output [:child/parent?]}
  (mapv (fn [input]
          (when (= parent-id (:parent/id input))
            {:child/parent? true}))
        inputs))


(def env (-> (pci/register
              (pa/auth-setup
               [toy
                child-toys
                favorite-toy
                child-parents
                parent?]))))

(comment
  ;; authorized, will return
  (let [query [{[:child/id 1] [{:child/toys [:toy/name]}]}]]
    @(p.a.eql/process (assoc env
                             ::p.a.eql/parallel? true
                             :parent-id 4) query))
  ;; => {[:child/id 1] #:child{:toys [#:toy{:name "Bobby"} #:toy{:name "Alice"} #:toy{:name "Rene"}]}}

  ;; unauthorized, will fail
  (let [query ]
    @(p.a.eql/process (assoc env ::p.a.eql/parallel? true)
                      [{[:child/id 1] [{:child/toys [:toy/name]}]}]query))


  )
