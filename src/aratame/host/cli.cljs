(ns aratame.host.cli
  "`aratame scan <path…>` and `aratame doctor`.

  Two things this CLI does that scanners usually do not:

  * A file it could not read becomes an `:unmeasured` verdict in the output and
    in the exit code. It is never skipped — a skipped file is invisible, and
    invisible files are how a partial sweep prints as a clean one.
  * Every governor refusal is printed. A gate whose refusals are filtered out
    of the report is indistinguishable from a gate that permitted everything."
  (:require ["node:crypto" :as crypto]
            ["node:fs" :as fs]
            ["node:path" :as path]
            [cljs.reader :as reader]
            [clojure.string :as str]
            [aratame.coverage :as cov]
            [aratame.governor :as gov]
            [aratame.host.probe :as probe]
            [aratame.indicators :as ind]
            [aratame.ledger :as led]
            [aratame.taxonomy :as tax]
            [aratame.verdict :as v]
            [nbb.core :as nbb]))

(defn digest
  "sha256 of the canonical string form. `clojure.core/hash` was here first and
  was wrong: a 32-bit non-cryptographic hash chains a ledger that a forger can
  collide by accident."
  [s]
  (.digest (doto (crypto/createHash "sha256") (.update s)) "hex"))

(def default-seed
  "The bundled seed, resolved from this file's own location rather than from the
  working directory. A cwd-relative default would make the tool answer
  `:unmeasured` for every file whenever it is invoked from elsewhere — a correct
  answer arrived at for the wrong reason, which is the worst kind."
  (path/resolve (path/dirname nbb/*file*) ".." ".." ".."
                "resources" "aratame" "indicators.seed.edn"))

;; ---------------------------------------------------------------------------
;; args
;; ---------------------------------------------------------------------------

(defn parse-args [argv]
  (loop [[a & more] argv opts {:paths []}]
    (cond
      (nil? a) opts
      (= "--indicators" a) (recur (rest more) (assoc opts :indicators (first more)))
      (= "--ledger" a)     (recur (rest more) (assoc opts :ledger (first more)))
      (= "--max-files" a)  (recur (rest more) (assoc opts :max-files (js/parseInt (first more))))
      (= "--audience" a)   (recur (rest more) (assoc opts :audience (keyword (first more))))
      (= "--edn" a)        (recur more (assoc opts :edn? true))
      (str/starts-with? (str a) "--") (recur more (update opts :unknown (fnil conj []) a))
      :else (recur more (update opts :paths conj a)))))

;; ---------------------------------------------------------------------------
;; indicator loading
;; ---------------------------------------------------------------------------

(defn load-indicators
  "Read an indicator file. A file that cannot be read yields an *undated* empty
  set rather than an empty set dated now — the difference is whether every
  subsequent verdict is `:unmeasured` or `:clean`, and reading failure must not
  buy the permissive one."
  [p]
  (try
    (let [d (reader/read-string (fs/readFileSync p "utf8"))]
      {:set (ind/indicator-set {:indicators (:indicators d)
                                :collected-at-ms (:set/collected-at-ms d)
                                :source-id (:set/source-id d)})
       :source p})
    (catch :default e
      {:set ind/empty-set :source p :error (.-message e)})))

;; ---------------------------------------------------------------------------
;; walking
;; ---------------------------------------------------------------------------

(defn walk
  "Regular files under `root`, breadth-bounded. Returns
  `{:files [...] :unreadable [...] :truncated? bool}` — the directories it could
  not open are returned, not swallowed."
  [root max-files]
  (loop [queue [root] files [] unreadable []]
    (cond
      (>= (count files) max-files) {:files files :unreadable unreadable :truncated? true}
      (empty? queue) {:files files :unreadable unreadable :truncated? false}
      :else
      (let [[p & more] queue]
        (let [st (try (fs/lstatSync p) (catch :default _ nil))]
          (cond
            (nil? st) (recur more files (conj unreadable p))
            (.isSymbolicLink st) (recur more files unreadable)
            (.isDirectory st)
            (let [kids (try (map #(path/join p %) (fs/readdirSync p))
                            (catch :default _ nil))]
              (if (nil? kids)
                (recur more files (conj unreadable p))
                (recur (concat more kids) files unreadable)))
            (.isFile st) (recur more (conj files p) unreadable)
            :else (recur more files unreadable)))))))

;; ---------------------------------------------------------------------------
;; scan
;; ---------------------------------------------------------------------------

(defn- proposed-action [verdict]
  (if (= :malicious (:verdict/value verdict)) :quarantine :report))

(defn judge-path [p {:keys [iset now audience]}]
  (let [{:keys [probes subject]} (probe/probe-file p)
        verdict (v/judge {:subject subject :probes probes
                          :indicator-set iset :now-ms now})
        action (proposed-action verdict)
        decision (gov/admit {:verdict verdict :action action
                             :subject subject :audience audience})]
    {:path p :subject subject :verdict verdict
     :proposed action :decision decision}))

(defn- unreadable-result [p]
  (let [verdict {:verdict/value :unmeasured
                 :verdict/reason [:probe/unanswered [:probe/sha256]]
                 :verdict/subject-id nil
                 :verdict/signals []}]
    {:path p :subject {:subject/path p} :verdict verdict
     :proposed :report
     :decision {:governor/decision :refuse :governor/reason :refuse/no-subject
                :governor/message (get tax/refusals :refuse/no-subject)}}))

(defn- line [{:keys [path verdict decision]}]
  (str/join "\t" [(str/upper-case (name (:verdict/value verdict)))
                  (pr-str (:verdict/reason verdict))
                  (name (:governor/decision decision))
                  (str (or (:governor/reason decision) ""))
                  path]))

(defn scan [{:keys [paths indicators ledger max-files audience edn?]}]
  (let [now (.now js/Date)
        {iset :set src :source err :error} (load-indicators (or indicators default-seed))
        stale (ind/staleness iset {:now-ms now :max-age-days (:indicators/max-age-days v/default-policy)})
        walked (map #(walk % (or max-files 5000)) paths)
        files (mapcat :files walked)
        unreadable (mapcat :unreadable walked)
        results (concat (map #(judge-path % {:iset iset :now now :audience audience}) files)
                        (map unreadable-result unreadable))
        summary (cov/summarize (map :verdict results) {:subjects-offered (count results)})]
    (when err
      (println (str "INDICATORS\tunreadable\t" src "\t" err)))
    (println (str "INDICATORS\t" src "\tcount=" (:set/count iset)
                  "\trejected=" (:set/rejected iset)
                  "\tstale=" (:stale? stale)
                  (when (:reason stale) (str "\treason=" (:reason stale)))))
    (doseq [r (sort-by #(- (tax/rank (get-in % [:verdict :verdict/value]))) results)]
      (println (line r)))
    (when (some :truncated? walked)
      (println (str "TRUNCATED\tmax-files=" (or max-files 5000)
                    "\tthe rest of the tree was not examined")))
    (println (cov/evidence-line summary))
    (println (str "ANSWER\t" (name (:coverage/answer summary))
                  "\tmalicious=" (get-in summary [:coverage/tally :malicious])
                  " suspicious=" (get-in summary [:coverage/tally :suspicious])
                  " unmeasured=" (get-in summary [:coverage/tally :unmeasured])
                  " clean=" (get-in summary [:coverage/tally :clean])))
    (when ledger
      (let [entries (reduce (fn [es r]
                              (-> es
                                  (led/append {:kind :verdict :at-ms now
                                               :payload (:verdict r)} digest)
                                  (led/append {:kind :governor :at-ms now
                                               :payload (assoc (:decision r)
                                                               :subject/id (get-in r [:subject :subject/id]))}
                                              digest)))
                            [] results)]
        (fs/writeFileSync ledger (str/join "\n" (map pr-str entries)))
        (println (str "LEDGER\t" ledger "\tentries=" (count entries)))))
    (when edn? (println (pr-str {:summary summary :results (vec results)})))
    (cov/exit-code summary)))

;; ---------------------------------------------------------------------------
;; doctor
;; ---------------------------------------------------------------------------

(defn doctor [{:keys [indicators]}]
  (let [now (.now js/Date)
        {iset :set src :source err :error} (load-indicators (or indicators default-seed))
        stale (ind/staleness iset {:now-ms now :max-age-days (:indicators/max-age-days v/default-policy)})
        plat (probe/platform-blocklist)]
    (println (str "PLATFORM\t" (name (:probe/status plat))
                  (when-let [x (get-in plat [:probe/value :xprotect :version])]
                    (str "\txprotect=" x))
                  (when-let [g (get-in plat [:probe/value :gatekeeper :status])]
                    (str "\tgatekeeper=" (name g)))))
    (println (str "INDICATORS\t" src "\tcount=" (:set/count iset)
                  "\tstale=" (:stale? stale)
                  (when (:reason stale) (str "\treason=" (:reason stale)))
                  (when err (str "\terror=" err))))
    (println "NOTE\tOn a Mac, XProtect is the antivirus. aratame judges what it is given"
             "and governs what may be done about it; it does not replace that.")
    (if (:stale? stale) 2 0)))

(defn -main [& argv]
  (let [[cmd & more] argv
        opts (parse-args more)]
    (set! (.-exitCode js/process)
          (case cmd
            "scan" (if (empty? (:paths opts))
                     (do (println "usage: aratame scan <path…> [--indicators f.edn] [--ledger f.edn] [--max-files n] [--edn]")
                         2)
                     (scan opts))
            "doctor" (doctor opts)
            (do (println "usage: aratame <scan|doctor> …") 2)))))
