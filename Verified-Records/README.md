# Document Verification Smart Contract

## Overview
This smart contract provides a secure and decentralized system for document verification on the Stacks blockchain. It allows users to register documents, assign verification permissions to trusted entities, and maintain an immutable record of document verification status.

## Features
- Document registration with content hashing for integrity verification
- Granular permission system for document access and verification
- Document revision tracking
- Comprehensive error handling and input validation
- Secure document modification with audit trail
- Role-based verification workflow

## Contract Structure

### Constants
- **Error Codes**: Descriptive error constants for better debugging and user feedback
- **Document Status**: Constants defining document verification states

### Data Structures
- **Document Structure**: Comprehensive document metadata including submitter, content hash, timestamps, and verification status
- **Document Registry**: Main storage for document records
- **Document Permissions**: Manages authorization for document viewing and verification

### Functions

#### Read-Only Functions
- `get-document-details`: Retrieves complete document information
- `check-verifier-permissions`: Checks if a principal has verification permissions for a document

#### Public Functions
- `register-new-document`: Registers a new document with metadata and content hash
- `modify-existing-document`: Updates an existing document with new content and metadata
- `approve-document`: Marks a document as verified by an authorized verifier
- `assign-document-permissions`: Grants document viewing and verification permissions
- `remove-document-permissions`: Revokes previously granted permissions

#### Private Helper Functions
- `validate-document-hash`: Ensures document hashes are valid
- `validate-document-metadata`: Validates document metadata format
- `validate-verifier-identity`: Validates verifier principal addresses
- `retrieve-document-safely`: Safely retrieves document data with error handling

## Error Codes
- `ERR-UNAUTHORIZED-USER-ACCESS (u100)`: Unauthorized access attempt
- `ERR-DOCUMENT-ALREADY-EXISTS (u101)`: Document ID already registered
- `ERR-DOCUMENT-DOES-NOT-EXIST (u102)`: Document ID not found
- `ERR-DOCUMENT-VERIFICATION-COMPLETE (u103)`: Attempt to modify a verified document
- `ERR-DOCUMENT-ID-INVALID-FORMAT (u104)`: Invalid document ID format
- `ERR-DOCUMENT-CONTENT-INVALID (u105)`: Invalid document content
- `ERR-DOCUMENT-METADATA-INVALID (u106)`: Invalid document metadata
- `ERR-VERIFIER-IDENTITY-INVALID (u107)`: Invalid verifier identity
- `ERR-FUNCTION-PARAMETER-INVALID (u108)`: Invalid function parameter
- `ERR-PERMISSION-DENIED (u109)`: Permission denied for the requested operation

## Usage Examples

### Registering a New Document
```clarity
(contract-call? .document-verification register-new-document 
    0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
    0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
    u"Document Title: Example Contract, Type: Legal, Date: 2025-03-15")
```

### Assigning Verification Permissions
```clarity
(contract-call? .document-verification assign-document-permissions
    0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
    'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM
    true
    true)
```

### Approving a Document
```clarity
(contract-call? .document-verification approve-document
    0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef)
```

## Security Considerations
- Only document owners can modify documents or assign permissions
- Documents cannot be modified after verification is complete
- Strict input validation for all function parameters
- Role-based access control for document verification
- Separation of viewing and verification permissions

## Implementation Notes
- Document IDs and content hashes must be 32-byte buffers
- Document metadata is limited to 256 bytes of UTF-8 encoded text
- Verifier principals cannot be the same as the document submitter or contract itself
- Document revision tracking increases with each modification