# Smart Contract Security Audit Tool

A comprehensive security auditing tool for Stacks smart contracts built with Clarity. This tool automatically analyzes smart contract code for common vulnerabilities and security issues, providing detailed reports and recommendations for developers.

## Features

### 🔍 **Automated Vulnerability Detection**
- **Reentrancy Attacks**: Detects potential reentrancy vulnerabilities in contract calls
- **Access Control Issues**: Identifies missing or improper authorization checks
- **Arithmetic Safety**: Catches potential overflow/underflow vulnerabilities
- **Timestamp Dependencies**: Flags risky reliance on block-height for critical logic
- **Error Handling**: Identifies improper error handling patterns

### 📊 **Code Analysis**
- Pattern recognition for security-critical code structures
- Complexity scoring and analysis
- Arithmetic operation detection
- Optional value handling assessment

### 🛡️ **Security Scoring**
- Comprehensive security score calculation (0-100)
- Severity-based vulnerability classification
- Historical audit tracking and comparison

### 🚨 **Emergency Controls**
- Emergency pause functionality for critical vulnerabilities
- Owner-only access controls for administrative functions

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd smart-contract-audit-tool

# Install dependencies
npm install

# Install Clarinet (if not already installed)
npm install -g @hirosystems/clarinet-cli
```

## Usage

### Running Security Audits

```typescript
// Perform a complete security audit
const auditResult = await performSecurityAudit(
  contractAddress,
  contractCode
);

console.log(`Audit ID: ${auditResult.auditId}`);
console.log(`Vulnerabilities found: ${auditResult.vulnerabilities}`);
console.log(`Severity Score: ${auditResult.severityScore}`);
```

### Analyzing Code Patterns

```typescript
// Analyze specific code patterns
const analysis = await analyzeCodePatterns(contractCode);

console.log(`Code complexity: ${analysis.complexityScore}`);
console.log(`Has arithmetic operations: ${analysis.hasArithmetic}`);
console.log(`Uses assertions: ${analysis.hasAssertions}`);
```

### Retrieving Audit Results

```typescript
// Get detailed audit results
const results = await getAuditResults(contractAddress, auditId);

console.log(`Vulnerabilities: ${results.vulnerabilitiesFound}`);
console.log(`Status: ${results.status}`);
console.log(`Auditor: ${results.auditor}`);
```

### Security Score Calculation

```typescript
// Get security score for a contract
const score = await getSecurityScore(contractAddress, auditId);
console.log(`Security Score: ${score}/100`);
```

## Vulnerability Types

### High Severity
- **Reentrancy**: Unprotected external calls that could lead to state manipulation
- **Access Control**: Missing authorization checks on critical functions

### Medium Severity  
- **Arithmetic Overflow**: Unsafe arithmetic operations without proper bounds checking
- **Timestamp Dependency**: Critical logic dependent on block-height values

### Low Severity
- **Improper Error Handling**: Insufficient error handling and validation

## Security Recommendations

The tool provides specific recommendations for each vulnerability type:

- **Reentrancy**: Implement checks-effects-interactions pattern
- **Access Control**: Add proper authorization checks with `asserts!`
- **Arithmetic Overflow**: Use `try!` and `asserts!` for safe arithmetic operations
- **Timestamp Dependency**: Avoid using block-height for critical business logic
- **Error Handling**: Implement comprehensive error handling with `try!` and `match`

## Testing

Run the comprehensive test suite:

```bash
# Run all tests
npm test

# Run specific test categories
npm test -- --grep "Code Pattern Analysis"
npm test -- --grep "Security Vulnerability Checks"
npm test -- --grep "Access Control"
```

### Test Coverage

The test suite covers:
- ✅ Code pattern analysis
- ✅ Vulnerability detection for all severity levels
- ✅ Security audit execution and result storage
- ✅ Access control mechanisms
- ✅ Edge cases (empty code, large contracts, secure contracts)
- ✅ Data integrity and audit history

## API Reference

### Core Functions

#### `perform-security-audit`
Performs a comprehensive security audit on a smart contract.

**Parameters:**
- `contract-address` (principal): The contract to audit
- `contract-code` (string-ascii): The contract source code

**Returns:**
- `audit-id` (uint): Unique identifier for the audit
- `vulnerabilities` (uint): Number of vulnerabilities found
- `severity-score` (uint): Overall severity score

#### `analyze-code-patterns`
Analyzes code patterns and complexity metrics.

**Parameters:**
- `code` (string-ascii): Contract source code to analyze

**Returns:**
- `length` (uint): Code length
- `has-arithmetic` (bool): Contains arithmetic operations
- `has-assertions` (bool): Uses assertion statements
- `has-optionals` (bool): Uses optional values
- `complexity-score` (uint): Code complexity rating

#### `get-audit-results`
Retrieves detailed results from a previous audit.

**Parameters:**
- `contract-address` (principal): Contract that was audited
- `audit-id` (uint): Audit identifier

**Returns:**
- `vulnerabilities-found` (uint): Number of vulnerabilities
- `severity-score` (uint): Severity assessment
- `timestamp` (uint): Audit completion time
- `auditor` (principal): Address that performed the audit
- `status` (string-ascii): Audit status

#### `get-security-score`
Calculates security score based on audit results.

**Parameters:**
- `contract-address` (principal): Contract to score
- `audit-id` (uint): Audit to base score on

**Returns:**
- Security score (0-100, where 100 is most secure)

### Emergency Functions

#### `emergency-pause`
Pauses contract operations in case of critical vulnerabilities.

**Access:** Contract owner only

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow existing code patterns and naming conventions
- Add comprehensive tests for new vulnerability detection rules
- Update documentation for new features
- Ensure all tests pass before submitting PRs

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security

This tool is designed to help identify security issues but should not be considered a complete security solution. Always conduct thorough manual reviews and consider professional security audits for production smart contracts.

## Support

For questions, issues, or contributions:
- Open an issue on GitHub
- Submit feature requests
- Join our community discussions

---

**Built for the Stacks ecosystem with ❤️**