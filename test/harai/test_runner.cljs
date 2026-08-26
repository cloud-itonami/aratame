(ns harai.test-runner
  "nbb test entry — `npm test`.

  nbb is the first-class runtime here (workspace runtime order: kotoba wasm >
  clojurewasm > ClojureScript > nbb, JVM last). The whole decision core is
  portable .cljc, so these same files run under a JVM runner too; nothing in
  the core requires one."
  (:require [cljs.test :as t]
            [harai.adapters-test]
            [harai.coverage-test]
            [harai.governor-test]
            [harai.indicators-test]
            [harai.ledger-test]
            [harai.verdict-test]))

(defmethod t/report [:cljs.test/default :end-run-tests] [m]
  (when-not (t/successful? m)
    (set! (.-exitCode js/process) 1)))

(defn -main [& _]
  (t/run-tests 'harai.verdict-test
               'harai.governor-test
               'harai.coverage-test
               'harai.indicators-test
               'harai.adapters-test
               'harai.ledger-test))
