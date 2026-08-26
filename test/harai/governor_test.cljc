(ns harai.governor-test
  "The gate, tested against the ways it could be talked into acting.

  The load-bearing test is `a-forged-verdict-does-not-convince-the-gate`: the
  governor recounts corroboration from the signals rather than reading
  `:verdict/value`, so an upstream that inflates its own verdict gains nothing."
  (:require [clojure.test :refer [deftest is testing]]
            [harai.governor :as gov]
            [harai.taxonomy :as tax]))

(defn signal [kind source]
  {:signal/kind kind :signal/source-id source :signal/id :signal/test
   :signal/confidence-permille 900 :signal/tlp :white})

(defn verdict [value signals & [{:keys [stale?]}]]
  {:verdict/value value
   :verdict/signals signals
   :verdict/subject-id "sha256:abc"
   :verdict/indicators {:stale? (boolean stale?) :age-days (if stale? 30 1)}})

(def two [(signal :indicator "threat-intelligence") (signal :signature "codesign")])

(defn subject [& [m]]
  (merge {:subject/id "sha256:abc" :subject/path "/Users/t/Downloads/thing"
          :subject/signature :unsigned}
         m))

(defn admit [& [m]]
  (gov/admit (merge {:verdict (verdict :malicious two)
                     :action :quarantine
                     :subject (subject)}
                    m)))

(deftest there-is-no-delete-opcode
  (testing "the vocabulary does not contain one"
    (is (not (contains? tax/actions :delete))))
  (testing "and asking for one is refused by name"
    (let [r (admit {:action :delete})]
      (is (= :refuse (:governor/decision r)))
      (is (= :refuse/action-not-admitted (:governor/reason r)))))
  (testing "control — the admitted action on the same input is permitted"
    (is (= :permit (:governor/decision (admit))))))

(deftest nothing-is-enforced-on-an-unmeasured-subject
  (let [r (admit {:verdict (verdict :unmeasured [])})]
    (is (= :refuse (:governor/decision r)))
    (is (= :refuse/verdict-unmeasured (:governor/reason r))))
  (testing "control — reporting an unmeasured subject is allowed, it touches nothing"
    (is (= :permit (:governor/decision (admit {:verdict (verdict :unmeasured [])
                                               :action :report}))))))

(deftest a-forged-verdict-does-not-convince-the-gate
  (testing "value says malicious, the signals say one accuser"
    (let [r (admit {:verdict (verdict :malicious [(signal :indicator "feed-a")])})]
      (is (= :escalate (:governor/decision r)))
      (is (= :escalate/uncorroborated (:governor/reason r)))
      (is (= 1 (get-in r [:governor/detail :corroboration])))))
  (testing "control — two independent signals under the same claim are permitted"
    (is (= :permit (:governor/decision (admit))))))

(deftest protected-paths-outrank-any-verdict
  (doseq [p ["/System/Library/CoreServices/x" "/usr/bin/x" "/Users/t/.ssh/id_ed25519"]]
    (let [r (admit {:subject (subject {:subject/path p})})]
      (is (= :refuse (:governor/decision r)) p)
      (is (= :refuse/protected-path (:governor/reason r)) p)))
  (testing "control — the same verdict outside those prefixes is permitted"
    (is (= :permit (:governor/decision (admit {:subject (subject {:subject/path "/Users/t/Downloads/x"})}))))))

(deftest platform-signed-binaries-are-never-touched
  (let [r (admit {:subject (subject {:subject/signature :apple-signed})})]
    (is (= :refuse (:governor/decision r)))
    (is (= :refuse/platform-signed (:governor/reason r)))))

(deftest enforcement-refuses-a-stale-indicator-set-by-default
  (let [r (admit {:verdict (verdict :malicious two {:stale? true})})]
    (is (= :refuse (:governor/decision r)))
    (is (= :refuse/indicators-stale (:governor/reason r))))
  (testing "an operator who has decided otherwise says so in policy"
    (is (= :permit (:governor/decision
                    (admit {:verdict (verdict :malicious two {:stale? true})
                            :policy {:enforce/require-fresh-indicators false}}))))))

(deftest a-public-citation-may-not-exceed-its-sharing-class
  (let [amber [(assoc (signal :indicator "feed-a") :signal/tlp :amber)
               (signal :signature "codesign")]
        r (admit {:verdict (verdict :malicious amber) :action :report :audience :public})]
    (is (= :refuse (:governor/decision r)))
    (is (= :refuse/tlp-disclosure (:governor/reason r))))
  (testing "control — the same disclosure to the operator is permitted"
    (let [amber [(assoc (signal :indicator "feed-a") :signal/tlp :amber)
                 (signal :signature "codesign")]]
      (is (= :permit (:governor/decision (admit {:verdict (verdict :malicious amber)
                                                 :action :report
                                                 :audience :operator})))))))

(deftest a-clean-subject-is-not-actionable
  (let [r (admit {:verdict (verdict :clean [])})]
    (is (= :refuse (:governor/decision r)))
    (is (= :refuse/no-corroboration (:governor/reason r)))))

(deftest every-reason-it-can-give-is-in-the-closed-set
  (let [reasons (->> [(admit {:action :delete})
                      (admit {:verdict (verdict :unmeasured [])})
                      (admit {:subject (subject {:subject/path "/usr/bin/x"})})
                      (admit {:subject (subject {:subject/signature :apple-signed})})
                      (admit {:verdict (verdict :malicious two {:stale? true})})
                      (admit {:verdict (verdict :clean [])})
                      (admit {:subject (dissoc (subject) :subject/id)})]
                     (map :governor/reason))]
    (is (every? #(contains? tax/refusals %) reasons))))
