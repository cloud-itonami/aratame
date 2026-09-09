(ns aratame.adapters
  "Translation from the shapes that already exist in this workspace into the
  two shapes this repository judges: an indicator, and a subject.

  Nothing here invents a vocabulary. `ti-record->indicator` takes
  cloud-itonami/threat-intelligence's `IndicatorRecord` field-for-field,
  `malware-sample->indicators` takes cloud-itonami/yabai's `MalwareSample`
  node, and `misogi-fact->subject` takes gftdcojp/misogi's fact map. When one
  of those changes shape, the translation is the thing that breaks — which is
  the point of having exactly one of them per producer."
  (:require [clojure.string :as str]))

(defn- get* [m & ks]
  (some (fn [k] (or (get m k) (get m (keyword k)) (get m (name k)))) ks))

(def ^:private tlp->kw
  {"white" :white "green" :green "amber" :amber "red" :red
   :white :white :green :green :amber :amber :red :red})

(def ^:private ti-type->kw
  {"ipv4" :ipv4 "ipv6" :ipv6 "domain" :domain "url" :url "md5" :md5
   "sha1" :sha1 "sha256" :sha256 "email" :email "cve" :cve})

(defn ti-record->indicator
  "One `IndicatorRecord` from cloud-itonami/threat-intelligence.

  `confidencePermille` is carried through unchanged rather than rescaled: it
  is already the registry's own 0–1000 permille scale, and a rescale here would
  make two numbers that mean the same thing disagree."
  [rec]
  (let [t (ti-type->kw (name (or (get* rec "indicatorType" "indicator-type") "")))]
    (when t
      {:indicator/type t
       :indicator/value (get* rec "value")
       :indicator/confidence-permille (get* rec "confidencePermille" "confidence-permille")
       :indicator/tlp (tlp->kw (get* rec "tlp"))
       :indicator/source-id (or (get* rec "source") "threat-intelligence")
       :indicator/last-seen (get* rec "lastSeen" "last-seen")
       :indicator/description (get* rec "description")})))

(defn malware-sample->indicators
  "One `MalwareSample` node from cloud-itonami/yabai fans out into the
  identifiers it names: its own hashes, and the C2 infrastructure it talks to.

  The C2 indicators carry lower confidence than the sample hashes on purpose —
  a hash identifies the sample, an address merely hosted it, and hosts are
  shared, reassigned and sinkholed."
  [{:keys [sha256 md5 family c2_domains c2_ips source] :as sample}]
  (let [src (or source "yabai")
        desc (when family (str "MalwareSample family " family))
        base {:indicator/source-id src :indicator/tlp :white
              :indicator/description desc
              :indicator/last-seen (get* sample "last_seen" "lastSeen")}]
    (vec (concat
          (when sha256 [(merge base {:indicator/type :sha256 :indicator/value sha256
                                     :indicator/confidence-permille 950})])
          (when md5 [(merge base {:indicator/type :md5 :indicator/value md5
                                  :indicator/confidence-permille 900})])
          (for [d (or c2_domains [])]
            (merge base {:indicator/type :domain :indicator/value d
                         :indicator/confidence-permille 600}))
          (for [ip (or c2_ips [])]
            (merge base {:indicator/type :ipv4 :indicator/value ip
                         :indicator/confidence-permille 550}))))))

(defn malware-sample->detections
  "`vt_detection_rate` as a reputation input. Returns nil when the field is
  absent — nil is not zero here: zero detections is a measurement, an absent
  field is not."
  [sample]
  (let [v (get* sample "vt_detection_rate" "vt-detection-rate")]
    (when (number? v) v)))

(defn misogi-fact->subject
  "A gftdcojp/misogi fact — the map its rules match against — as a subject.

  misogi decides what to do with a Mac's own files; aratame decides whether a
  thing is malicious. Feeding one into the other is the whole integration, so
  this function is deliberately the only place that knows both shapes."
  [{:keys [path bundle-id program persistence signature sha256 md5] :as fact}]
  {:subject/id (or sha256 path bundle-id)
   :subject/path (or program path)
   :subject/sha256 sha256
   :subject/md5 md5
   :subject/signature (or signature :unknown)
   :subject/persistence persistence
   :subject/bundle-id bundle-id
   :subject/quarantine-xattr (get* fact "quarantine-xattr" "quarantined?")
   :subject/hidden? (boolean (when program
                               (or (str/starts-with? program "/tmp/")
                                   (str/starts-with? program "/private/tmp/"))))})
