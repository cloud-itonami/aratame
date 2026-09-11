(ns aratame.ledger
  "Append-only records of every verdict and every governor decision.

  A refusal is recorded with the same weight as a permission. A gate whose
  refusals leave no trace is indistinguishable from a gate that was never
  consulted, and the second one is what an auditor will assume."
  (:require [kotoba.lang.text :as str]))

(defn entry
  "One ledger record. `digest-fn` hashes the canonical string form; the host
  supplies it because hashing is not a pure-core capability. Chaining is by
  `:ledger/prev`, so a removed record leaves a hole that does not close."
  [{:keys [seq prev kind payload at-ms actor]} digest-fn]
  (let [body {:ledger/seq seq
              :ledger/prev prev
              :ledger/kind kind
              :ledger/at-ms at-ms
              :ledger/actor (or actor "aratame")
              :ledger/payload payload}]
    (assoc body :ledger/digest (digest-fn (pr-str body)))))

(defn append
  "Append one entry, chaining from the last digest."
  [entries m digest-fn]
  (conj (vec entries)
        (entry (assoc m
                      :seq (count entries)
                      :prev (:ledger/digest (last entries)))
               digest-fn)))

(defn verify
  "Recompute every digest and every link. `:entries` is returned alongside
  `:ok?` so that a caller cannot read 'nothing was wrong' as 'something was
  checked' — an empty ledger is `{:ok? true :entries 0}`, and those are two
  different facts."
  [entries digest-fn]
  (let [broken (->> entries
                    (map-indexed
                     (fn [i e]
                       (let [body (dissoc e :ledger/digest)
                             expect (digest-fn (pr-str body))
                             prev (:ledger/digest (nth (vec entries) (dec i) nil))]
                         (cond
                           (not= expect (:ledger/digest e)) {:at i :fault :digest}
                           (and (pos? i) (not= prev (:ledger/prev e))) {:at i :fault :chain}
                           :else nil))))
                    (remove nil?)
                    vec)]
    {:ok? (empty? broken) :broken broken :entries (count entries)}))

(defn render-line [e]
  (let [d (str (:ledger/digest e))]
    (str/join "\t" [(:ledger/seq e) (name (:ledger/kind e))
                    (get-in e [:ledger/payload :subject/id] "-")
                    (subs d 0 (min 12 (count d)))])))
