# Pathauth

  Pathauth is designed to set up fine grained authorizations of resolvers as an orthogonal
  concern without compromising on performances and complexity.
  
  As a developer, all you have to do is write the authorization resolvers that will resolve authorization attributes and to use these authorization attributes in the `::pa/auth` key of other resolvers' config.
  
  The idea is to leverage the pathom planner to figure out on its own how to find the attributes needed to establish if the access to a particular attribute is authorized or not.
  
 As a result an authorization can depend on any accessible attribute, or even on another authorization. If a path exists to solve the authorization, even a recursive one, Pathom will find it. And there is little to worry about performance, as batching and caching will perform with a minimal number of calls (eg to the database).

## Alpha warning

Current status:
- used with `fulcro-rad`, `::pa/auth` is added to attributes that require authorization.
- parser must be used in lenient mode
- queries are authorized with `(pa/auth-query authorization-attributes query)`
```clojure
(def auth-attributes (pa/auth-attributes all-attributes :production))
(def my-query (pa/auth-query auth-attributes tx))
```

- middleware needs to throw on resolver error and response needs to be cleaned up when ex-data `:unauthorized` is true

```clojure
(p.plugin/register
       {::p.plugin/id 'err
        :com.wsscode.pathom3.connect.runner/wrap-resolver-error
        (fn [_]
          (fn [env node error]
            (if (= "Unauthorized" (ex-message error))
              (throw (ex-info "Unauthorized" {:unauthorized true}))
              (do
                (log/error (ex-message error) error)
                (ex-message error)))))})
```

```clojure
(if (-> response :com.wsscode.pathom3.error/error-data :unauthorized)
          "Unauthorized"
          response)
```
The development of Pathauth is still really early stage:
- no automated tests
- expected API breakage
- potential bugs

For these reasons the current way to use it is via deps.edn git/url:
```clojure
yenda/pathauth {:git/url "https://github.com/yenda/pathauth.git"
                :sha "latestsha"}
```

## Getting started

To set up fine grained authorization of your resolver, all you need to do is:
- [write at least one authorization resolver](#authorization-resolver)
- [add authorizations to your resolvers' config](#simple-resolver-with-authorization)


### Authorization resolver

A classic Pathom resolver whose outputs are authorization attributes.

Inputs can be any arbitrary attribute that is needed to determine that the authorizations are granted.
Outputs are the authorization attributes that will be used in the `::pa/auth` config of other resolver.

They return nothing or throw unauthorized if the authorization is not granted.

```clojure
(pco/defresolver parent?
  [{:keys [parent-id] :as env} inputs]
  {::pco/input  [:child/id :parent/id]
   ::pco/batch? true
   ::pco/output [:child/parent?]}
  (mapv (fn [input]
          (when-not (= parent-id (:parent/id input))
            (throw (ex-date "Unauthorized" {}))))))
```


### Simple resolver with authorization

To add authorization to a resolver you simply add `::pa/auth` to their config with the desired authorization attributes.

## Library development

Run the project's tests:

    $ clojure -T:build test

Run the project's CI pipeline and build a JAR:

    $ clojure -T:build ci

This will produce an updated `pom.xml` file with synchronized dependencies inside the `META-INF`
directory inside `target/classes` and the JAR in `target`. You can update the version (and SCM tag)
information in generated `pom.xml` by updating `build.clj`.

Install it locally (requires the `ci` task be run first):

    $ clojure -T:build install

Deploy it to Clojars -- needs `CLOJARS_USERNAME` and `CLOJARS_PASSWORD` environment
variables (requires the `ci` task be run first):

    $ clojure -T:build deploy

Your library will be deployed to net.clojars.yenda/pathauth on clojars.org by default.

## License

Copyright © 2023 Yenda

Distributed under the Eclipse Public License version 1.0.
