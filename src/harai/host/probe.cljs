(ns harai.host.probe
  "The effectful edge: hashing a file, asking macOS what it thinks of it, and
  saying so honestly when it cannot ask.

  Every probe returns `{:probe/status :answered | :unavailable | :error}` and
  never a bare value. That is the whole reason this layer is separate: a probe
  that returns `:unsigned` when it could not run, or an empty result when it was
  denied, is the mechanism by which an unexamined machine reports as clean.

  Signing state and quarantine provenance come from
  `kotoba-lang/macos-inventory`, which owns the codesign/spctl parsing. They are
  not re-implemented here."
  (:require ["node:crypto" :as crypto]
            ["node:fs" :as fs]
            [macos-inventory.host :as inv]))

(defn darwin? [] (= "darwin" (.-platform js/process)))

(defn sha256-file
  "sha256 of a file's bytes. An unreadable file is `:error` with the errno —
  not a hash of nothing."
  [path]
  (try
    (let [buf (fs/readFileSync path)
          h (doto (crypto/createHash "sha256") (.update buf))]
      {:probe/status :answered :probe/value (.digest h "hex")
       :probe/bytes (.-length buf)})
    (catch :default e
      {:probe/status :error :probe/detail (.-message e)})))

(defn md5-file [path]
  (try
    (let [buf (fs/readFileSync path)]
      {:probe/status :answered
       :probe/value (.digest (doto (crypto/createHash "md5") (.update buf)) "hex")})
    (catch :default e {:probe/status :error :probe/detail (.-message e)})))

(defn signature
  "Code-signing verdict. On a machine that is not macOS this is `:unavailable`,
  which propagates all the way to an `:unmeasured` verdict — the correct answer,
  because nothing here can judge a Mach-O signature off a Mac."
  [path]
  (if-not (darwin?)
    {:probe/status :unavailable :probe/detail "not darwin"}
    (try
      {:probe/status :answered :probe/value (inv/signature path)}
      (catch :default e {:probe/status :error :probe/detail (.-message e)}))))

(defn quarantine-xattr
  "Whether the file carries `com.apple.quarantine` — how it arrived, not what
  it is."
  [path]
  (if-not (darwin?)
    {:probe/status :unavailable :probe/detail "not darwin"}
    (try
      {:probe/status :answered :probe/value (boolean (inv/quarantined? path))}
      (catch :default e {:probe/status :error :probe/detail (.-message e)}))))

(defn platform-blocklist
  "Apple's own malware blocklist version and Gatekeeper's state.

  harai reports this because it is more consequential than any list harai
  ships: on a Mac, XProtect is the antivirus, and the honest position of this
  repository is to say how current it is rather than to compete with it."
  []
  (if-not (darwin?)
    {:probe/status :unavailable :probe/detail "not darwin"}
    (try
      {:probe/status :answered
       :probe/value {:xprotect (inv/xprotect-version) :gatekeeper (inv/gatekeeper)}}
      (catch :default e {:probe/status :error :probe/detail (.-message e)}))))

(defn probe-file
  "Every probe for one path, as the map `harai.verdict/judge` consumes, plus
  the subject facts those probes established."
  [path]
  (let [h (sha256-file path)
        m (md5-file path)
        s (signature path)
        q (quarantine-xattr path)]
    {:probes {:probe/sha256 h :probe/signature s}
     :subject {:subject/id (when (= :answered (:probe/status h))
                             (str "sha256:" (:probe/value h)))
               :subject/path path
               :subject/sha256 (when (= :answered (:probe/status h)) (:probe/value h))
               :subject/md5 (when (= :answered (:probe/status m)) (:probe/value m))
               :subject/signature (when (= :answered (:probe/status s)) (:probe/value s))
               :subject/quarantine-xattr (when (= :answered (:probe/status q))
                                           (:probe/value q))
               :subject/bytes (:probe/bytes h)}}))
