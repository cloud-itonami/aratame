(ns aratame.coverage
  "What a sweep is allowed to claim.

  A sweep that examined nothing and a sweep that examined everything and found
  nothing produce the same sentence in every antivirus product ever shipped:
  no threats found. So this namespace refuses the first one. A summary over an
  empty verdict list is not clean — it is `:refused`, and it says why.

  The exit codes follow the same rule: `2` is reserved for *could not answer*
  and is neither the success code nor the found-something code, so a caller
  that only checks `if exit == 0` cannot read an unanswered sweep as success."
  (:require [aratame.taxonomy :as tax]))

(defn tally [verdicts]
  (reduce (fn [m v] (update m (:verdict/value v) (fnil inc 0)))
          {:malicious 0 :suspicious 0 :unmeasured 0 :clean 0}
          verdicts))

(defn summarize
  "`verdicts` -> a summary that can be printed, transported and audited.

  `:coverage/answer` is one of `:refused` (nothing was examined),
  `:partial` (something was examined but some subjects could not be judged),
  or `:complete`."
  [verdicts {:keys [subjects-offered]}]
  (let [n (count verdicts)
        t (tally verdicts)
        answer (cond (zero? n)                :refused
                     (pos? (:unmeasured t 0)) :partial
                     :else                    :complete)]
    {:coverage/answer   answer
     :coverage/reason   (when (= :refused answer) :coverage/no-evidence)
     :coverage/scanned  n
     :coverage/offered  (or subjects-offered n)
     :coverage/tally    t
     :coverage/highest  (->> verdicts (map :verdict/value)
                             (sort-by (comp - tax/rank)) first)}))

(defn evidence-line
  "The one line an automated caller greps for. A run that would print
  a zero count is not reporting a clean tree; `summarize` has already refused."
  [summary]
  (str "SCANNED\t" (:coverage/scanned summary)))

(defn exit-code
  "0 nothing found · 1 something found · 2 could not answer.

  `:partial` maps to 2 even when nothing was found in the part that was
  examined, because the unexamined part is exactly what was being asked about."
  [summary]
  (let [t (:coverage/tally summary)]
    (cond
      (= :refused (:coverage/answer summary))          2
      (pos? (+ (:malicious t 0) (:suspicious t 0)))    1
      (pos? (:unmeasured t 0))                         2
      :else                                            0)))
