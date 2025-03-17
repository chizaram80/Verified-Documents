;; Document Verification Smart Contract

;; Error codes
(define-constant ERR-UNAUTHORIZED-USER-ACCESS (err u100))
(define-constant ERR-DOCUMENT-ALREADY-EXISTS (err u101))
(define-constant ERR-DOCUMENT-DOES-NOT-EXIST (err u102))
(define-constant ERR-DOCUMENT-VERIFICATION-COMPLETE (err u103))
(define-constant ERR-DOCUMENT-ID-INVALID-FORMAT (err u104))
(define-constant ERR-DOCUMENT-CONTENT-INVALID (err u105))
(define-constant ERR-DOCUMENT-METADATA-INVALID (err u106))
(define-constant ERR-VERIFIER-IDENTITY-INVALID (err u107))
(define-constant ERR-FUNCTION-PARAMETER-INVALID (err u108))
(define-constant ERR-PERMISSION-DENIED (err u109))
(define-constant ERR-NULL-INPUT (err u110))

;; Constants for document verification status
(define-constant DOC-STATUS-AWAITING-VERIFICATION "PENDING")
(define-constant DOC-STATUS-VERIFICATION-COMPLETE "VERIFIED")

;; Define document record structure
(define-data-var document-structure-template 
    {
        submitter-principal: principal,
        content-hash: (buff 32),
        submission-timestamp: uint,
        verification-status: (string-ascii 20),
        verifier-identity: (optional principal),
        document-metadata: (string-utf8 256),
        document-revision: uint,
        verification-completed: bool
    }
    {
        submitter-principal: tx-sender,
        content-hash: 0x0000000000000000000000000000000000000000000000000000000000000000,
        submission-timestamp: u0,
        verification-status: DOC-STATUS-AWAITING-VERIFICATION,
        verifier-identity: none,
        document-metadata: u"",
        document-revision: u0,
        verification-completed: false
    }
)

;; Data maps
(define-map document-registry
    { document-id: (buff 32) }
    {
        submitter-principal: principal,
        content-hash: (buff 32),
        submission-timestamp: uint,
        verification-status: (string-ascii 20),
        verifier-identity: (optional principal),
        document-metadata: (string-utf8 256),
        document-revision: uint,
        verification-completed: bool
    }
)

(define-map document-permissions
    { document-id: (buff 32), authorized-verifier: principal }
    { has-view-permission: bool, has-verification-permission: bool }
)

;; Basic input validation functions
(define-private (is-valid-buff-32 (input (buff 32)))
    (is-eq (len input) u32))

(define-private (is-valid-string-utf8 (input (string-utf8 256)))
    (and (<= (len input) u256) (> (len input) u0)))

;; Enhanced validation functions with pre-checks
(define-private (validate-document-hash (document-hash-input (buff 32)))
    (if (is-valid-buff-32 document-hash-input)
        (ok document-hash-input)
        ERR-FUNCTION-PARAMETER-INVALID))

(define-private (validate-document-metadata (metadata-content (string-utf8 256)))
    (if (is-valid-string-utf8 metadata-content)
        (ok metadata-content)
        ERR-FUNCTION-PARAMETER-INVALID))

(define-private (validate-verifier-identity (verifier-principal principal))
    (if (and 
        (not (is-eq verifier-principal tx-sender))
        (not (is-eq verifier-principal (as-contract tx-sender))))
        (ok verifier-principal)
        ERR-VERIFIER-IDENTITY-INVALID))

;; Safe input validation helpers
(define-private (safe-validate-document-hash (doc-id (buff 32)))
    (begin
        (asserts! (is-valid-buff-32 doc-id) ERR-DOCUMENT-ID-INVALID-FORMAT)
        (validate-document-hash doc-id)))

(define-private (safe-validate-document-metadata (metadata (string-utf8 256)))
    (begin
        (asserts! (is-valid-string-utf8 metadata) ERR-DOCUMENT-METADATA-INVALID)
        (validate-document-metadata metadata)))

(define-private (safe-validate-verifier-identity (verifier principal))
    (begin
        (asserts! (not (is-eq verifier tx-sender)) ERR-VERIFIER-IDENTITY-INVALID)
        (validate-verifier-identity verifier)))

;; Safe document retrieval with better error handling
(define-private (retrieve-document-safely (doc-id (buff 32)))
    (begin
        (asserts! (is-valid-buff-32 doc-id) ERR-DOCUMENT-ID-INVALID-FORMAT)
        (let ((validated-doc-id-result (validate-document-hash doc-id)))
            (match validated-doc-id-result
                validated-doc-id (match (map-get? document-registry { document-id: validated-doc-id })
                    document-data (ok document-data)
                    ERR-DOCUMENT-DOES-NOT-EXIST)
                error (err error)))))

;; Read-only functions
(define-read-only (get-document-details (doc-id (buff 32)))
    (begin
        (asserts! (is-valid-buff-32 doc-id) ERR-DOCUMENT-ID-INVALID-FORMAT)
        (retrieve-document-safely doc-id)))

(define-read-only (check-verifier-permissions (doc-id (buff 32)) (verifier-principal principal))
    (begin
        (asserts! (is-valid-buff-32 doc-id) ERR-DOCUMENT-ID-INVALID-FORMAT)
        (asserts! (not (is-eq verifier-principal tx-sender)) ERR-VERIFIER-IDENTITY-INVALID)
        (let ((validated-doc-id-result (safe-validate-document-hash doc-id))
              (validated-verifier-result (safe-validate-verifier-identity verifier-principal)))
            (match validated-doc-id-result
                validated-doc-id 
                (match validated-verifier-result
                    validated-verifier 
                    (match (map-get? document-permissions 
                        { document-id: validated-doc-id, authorized-verifier: validated-verifier })
                        permission-info (ok permission-info)
                        (ok { has-view-permission: false, has-verification-permission: false }))
                    error (err error))
                error (err error)))))

;; Public functions with enhanced security
(define-public (register-new-document 
    (doc-id (buff 32))
    (doc-content-hash (buff 32))
    (doc-metadata (string-utf8 256)))
    (begin
        ;; Add explicit checks for input parameters
        (asserts! (is-valid-buff-32 doc-id) ERR-DOCUMENT-ID-INVALID-FORMAT)
        (asserts! (is-valid-buff-32 doc-content-hash) ERR-DOCUMENT-CONTENT-INVALID)
        (asserts! (is-valid-string-utf8 doc-metadata) ERR-DOCUMENT-METADATA-INVALID)
        
        (let ((validated-doc-id-result (safe-validate-document-hash doc-id))
              (validated-content-result (safe-validate-document-hash doc-content-hash))
              (validated-metadata-result (safe-validate-document-metadata doc-metadata)))
            (match validated-doc-id-result
                validated-doc-id 
                (match validated-content-result
                    validated-content 
                    (match validated-metadata-result
                        validated-metadata 
                        (match (map-get? document-registry { document-id: validated-doc-id })
                            existing-document ERR-DOCUMENT-ALREADY-EXISTS
                            (ok (map-set document-registry
                                { document-id: validated-doc-id }
                                {
                                    submitter-principal: tx-sender,
                                    content-hash: validated-content,
                                    submission-timestamp: block-height,
                                    verification-status: DOC-STATUS-AWAITING-VERIFICATION,
                                    verifier-identity: none,
                                    document-metadata: validated-metadata,
                                    document-revision: u1,
                                    verification-completed: false
                                })))
                        error (err error))
                    error (err error))
                error (err error)))))

(define-public (modify-existing-document
    (doc-id (buff 32))
    (updated-content-hash (buff 32))
    (updated-metadata (string-utf8 256)))
    (begin
        ;; Add explicit checks for input parameters
        (asserts! (is-valid-buff-32 doc-id) ERR-DOCUMENT-ID-INVALID-FORMAT)
        (asserts! (is-valid-buff-32 updated-content-hash) ERR-DOCUMENT-CONTENT-INVALID)
        (asserts! (is-valid-string-utf8 updated-metadata) ERR-DOCUMENT-METADATA-INVALID)
        
        (let ((validated-doc-id-result (safe-validate-document-hash doc-id))
              (validated-content-result (safe-validate-document-hash updated-content-hash))
              (validated-metadata-result (safe-validate-document-metadata updated-metadata)))
            (match validated-doc-id-result
                validated-doc-id 
                (begin
                    (asserts! (is-some (map-get? document-registry { document-id: validated-doc-id })) ERR-DOCUMENT-DOES-NOT-EXIST)
                    (let ((existing-document (unwrap-panic (map-get? document-registry { document-id: validated-doc-id }))))
                        (match validated-content-result
                            validated-content 
                            (match validated-metadata-result
                                validated-metadata 
                                (begin
                                    (asserts! (is-eq (get submitter-principal existing-document) tx-sender) ERR-UNAUTHORIZED-USER-ACCESS)
                                    (asserts! (not (get verification-completed existing-document)) ERR-DOCUMENT-VERIFICATION-COMPLETE)
                                    (ok (map-set document-registry
                                        { document-id: validated-doc-id }
                                        (merge existing-document
                                            {
                                                content-hash: validated-content,
                                                document-metadata: validated-metadata,
                                                submission-timestamp: block-height,
                                                document-revision: (+ (get document-revision existing-document) u1),
                                                verification-completed: false
                                            }))))
                                error (err error))
                            error (err error))))
                error (err error)))))

(define-public (approve-document (doc-id (buff 32)))
    (begin
        ;; Add explicit check for input parameter
        (asserts! (is-valid-buff-32 doc-id) ERR-DOCUMENT-ID-INVALID-FORMAT)
        
        (let ((validated-doc-id-result (safe-validate-document-hash doc-id)))
            (match validated-doc-id-result
                validated-doc-id
                (begin
                    (asserts! (is-some (map-get? document-registry { document-id: validated-doc-id })) ERR-DOCUMENT-DOES-NOT-EXIST)
                    (let ((existing-document (unwrap-panic (map-get? document-registry { document-id: validated-doc-id }))))
                        (let ((permissions-result (check-verifier-permissions validated-doc-id tx-sender)))
                            (match permissions-result
                                permissions-value
                                (begin
                                    (asserts! (get has-verification-permission permissions-value) ERR-UNAUTHORIZED-USER-ACCESS)
                                    (asserts! (not (get verification-completed existing-document)) ERR-DOCUMENT-VERIFICATION-COMPLETE)
                                    (ok (map-set document-registry
                                        { document-id: validated-doc-id }
                                        (merge existing-document
                                            {
                                                verification-status: DOC-STATUS-VERIFICATION-COMPLETE,
                                                verifier-identity: (some tx-sender),
                                                verification-completed: true
                                            }))))
                                error-value ERR-UNAUTHORIZED-USER-ACCESS))))
                error (err error)))))

(define-public (assign-document-permissions
    (doc-id (buff 32))
    (authorized-verifier principal)
    (grant-viewing-access bool)
    (grant-verification-access bool))
    (begin
        ;; Add explicit checks for input parameters
        (asserts! (is-valid-buff-32 doc-id) ERR-DOCUMENT-ID-INVALID-FORMAT)
        (asserts! (not (is-eq authorized-verifier tx-sender)) ERR-VERIFIER-IDENTITY-INVALID)
        
        (let ((validated-doc-id-result (safe-validate-document-hash doc-id))
              (validated-verifier-result (safe-validate-verifier-identity authorized-verifier)))
            (match validated-doc-id-result
                validated-doc-id
                (begin
                    (asserts! (is-some (map-get? document-registry { document-id: validated-doc-id })) ERR-DOCUMENT-DOES-NOT-EXIST)
                    (let ((existing-document (unwrap-panic (map-get? document-registry { document-id: validated-doc-id }))))
                        (match validated-verifier-result
                            validated-verifier
                            (begin
                                (asserts! (is-eq (get submitter-principal existing-document) tx-sender) ERR-UNAUTHORIZED-USER-ACCESS)
                                (ok (map-set document-permissions
                                    { document-id: validated-doc-id, authorized-verifier: validated-verifier }
                                    { 
                                        has-view-permission: grant-viewing-access, 
                                        has-verification-permission: grant-verification-access 
                                    })))
                            error (err error))))
                error (err error)))))

(define-public (remove-document-permissions
    (doc-id (buff 32))
    (authorized-verifier principal))
    (begin
        ;; Add explicit checks for input parameters
        (asserts! (is-valid-buff-32 doc-id) ERR-DOCUMENT-ID-INVALID-FORMAT)
        (asserts! (not (is-eq authorized-verifier tx-sender)) ERR-VERIFIER-IDENTITY-INVALID)
        
        (let ((validated-doc-id-result (safe-validate-document-hash doc-id))
              (validated-verifier-result (safe-validate-verifier-identity authorized-verifier)))
            (match validated-doc-id-result
                validated-doc-id
                (begin
                    (asserts! (is-some (map-get? document-registry { document-id: validated-doc-id })) ERR-DOCUMENT-DOES-NOT-EXIST)
                    (let ((existing-document (unwrap-panic (map-get? document-registry { document-id: validated-doc-id }))))
                        (match validated-verifier-result
                            validated-verifier
                            (begin
                                (asserts! (is-eq (get submitter-principal existing-document) tx-sender) ERR-UNAUTHORIZED-USER-ACCESS)
                                (ok (map-delete document-permissions
                                    { document-id: validated-doc-id, authorized-verifier: validated-verifier })))
                            error (err error))))
                error (err error)))))