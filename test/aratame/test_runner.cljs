(ns aratame.test-runner
  "nbb test entry — `npm test`.

  nbb is the first-class runtime here (workspace runtime order: kotoba wasm >
  clojurewasm > ClojureScript > nbb, JVM last). The whole decision core is
  portable .cljc, so these same files run under a JVM runner too; nothing in
  the core requires one."
  (:require [cljs.test :as t]
            [aratame.adapters-test]
            [aratame.coverage-test]
            [aratame.governor-test]
            [aratame.indicators-test]
            [aratame.ledger-test]
            [aratame.verdict-test]))

(defmethod t/report [:cljs.test/default :end-run-tests] [m]
  (when-not (t/successful? m)
    (set! (.-exitCode js/process) 1)))

(defn -main [& _]
  (t/run-tests 'aratame.verdict-test
               'aratame.governor-test
               'aratame.coverage-test
               'aratame.indicators-test
               'aratame.adapters-test
               'aratame.ledger-test))
