"""Banking Application Templates & Profiles.

Pre-configured templates for every type of banking application found globally,
covering retail banking, corporate banking, payment systems, regulatory,
capital markets, insurance, and fintech platforms.
"""

# ─────────────────────────── BANKING APP CATEGORIES ───────────────────────────

BANKING_CATEGORIES = {
    "retail_banking": {
        "label": "Retail / Consumer Banking",
        "description": "Customer-facing internet and mobile banking platforms",
        "icon": "user",
    },
    "corporate_banking": {
        "label": "Corporate & Institutional Banking",
        "description": "Business banking, treasury, trade finance portals",
        "icon": "building",
    },
    "payment_systems": {
        "label": "Payment & Transaction Systems",
        "description": "Payment gateways, card processing, UPI, SWIFT, RTGS",
        "icon": "credit-card",
    },
    "capital_markets": {
        "label": "Capital Markets & Trading",
        "description": "Trading platforms, order management, market data feeds",
        "icon": "trending-up",
    },
    "risk_compliance": {
        "label": "Risk, Compliance & Regulatory",
        "description": "AML, KYC, fraud detection, regulatory reporting",
        "icon": "shield",
    },
    "core_banking": {
        "label": "Core Banking Systems",
        "description": "CBS, account management, ledger, loan origination",
        "icon": "database",
    },
    "digital_channels": {
        "label": "Digital Channels & APIs",
        "description": "Open Banking APIs, BaaS, mobile wallets, chatbots",
        "icon": "smartphone",
    },
    "insurance": {
        "label": "Insurance & Wealth Management",
        "description": "Insurance portals, wealth management, robo-advisors",
        "icon": "umbrella",
    },
    "infrastructure": {
        "label": "Banking Infrastructure",
        "description": "ATM networks, HSM, PKI, SIEM, SOC platforms",
        "icon": "server",
    },
    "fintech": {
        "label": "Fintech & Neo-Banking",
        "description": "Digital-only banks, lending platforms, crypto exchanges",
        "icon": "zap",
    },
}

# ─────────────────────────── BANKING APP TEMPLATES ───────────────────────────

BANKING_TEMPLATES = [
    # ━━━ RETAIL / CONSUMER BANKING ━━━
    {"id": "inet_banking", "name": "Internet Banking Portal", "category": "retail_banking",
     "asset_type": "web_server", "default_port": 443, "criticality": "critical",
     "description": "Customer-facing online banking with account management, fund transfers, bill payments",
     "scan_profile": "full", "compliance": ["pci_dss", "rbi_cyber", "gdpr"],
     "expected_tls": "TLSv1.2+", "requires_pfs": True, "requires_hsts": True},

    {"id": "mobile_banking_api", "name": "Mobile Banking API", "category": "retail_banking",
     "asset_type": "api", "default_port": 443, "criticality": "critical",
     "description": "REST/GraphQL APIs serving iOS and Android banking apps",
     "scan_profile": "api_full", "compliance": ["pci_dss", "owasp_api"],
     "expected_tls": "TLSv1.2+", "requires_pfs": True, "requires_cert_pinning": True},

    {"id": "customer_onboarding", "name": "Digital Customer Onboarding", "category": "retail_banking",
     "asset_type": "web_server", "default_port": 443, "criticality": "high",
     "description": "eKYC, video KYC, account opening portal with Aadhaar/PAN verification",
     "scan_profile": "full", "compliance": ["pci_dss", "rbi_kyc", "gdpr"]},

    {"id": "loan_portal", "name": "Loan Application Portal", "category": "retail_banking",
     "asset_type": "web_server", "default_port": 443, "criticality": "high",
     "description": "Online loan applications — personal, home, vehicle, education loans",
     "scan_profile": "full", "compliance": ["pci_dss", "rbi_cyber"]},

    {"id": "credit_card_portal", "name": "Credit Card Management Portal", "category": "retail_banking",
     "asset_type": "web_server", "default_port": 443, "criticality": "critical",
     "description": "Card management, statements, limit changes, reward redemption",
     "scan_profile": "full", "compliance": ["pci_dss"]},

    {"id": "wealth_mgmt_retail", "name": "Retail Investment Portal", "category": "retail_banking",
     "asset_type": "web_server", "default_port": 443, "criticality": "high",
     "description": "Mutual funds, fixed deposits, recurring deposits, SIP management",
     "scan_profile": "full", "compliance": ["pci_dss", "sebi"]},

    {"id": "demat_portal", "name": "Demat Account Portal", "category": "retail_banking",
     "asset_type": "web_server", "default_port": 443, "criticality": "high",
     "description": "Depository participant services, share holding, IPO applications",
     "scan_profile": "full", "compliance": ["sebi", "pci_dss"]},

    {"id": "insurance_portal", "name": "Bancassurance Portal", "category": "retail_banking",
     "asset_type": "web_server", "default_port": 443, "criticality": "medium",
     "description": "Insurance product sales, policy management, claims",
     "scan_profile": "full", "compliance": ["irdai", "pci_dss"]},

    {"id": "pension_portal", "name": "Pension & NPS Portal", "category": "retail_banking",
     "asset_type": "web_server", "default_port": 443, "criticality": "high",
     "description": "National Pension System, APY, PPF management",
     "scan_profile": "full", "compliance": ["pfrda", "rbi_cyber"]},

    {"id": "remittance_portal", "name": "Remittance & Money Transfer", "category": "retail_banking",
     "asset_type": "web_server", "default_port": 443, "criticality": "critical",
     "description": "Domestic and international money transfers, NEFT, RTGS, IMPS",
     "scan_profile": "full", "compliance": ["pci_dss", "rbi_cyber", "fatf"]},

    # ━━━ CORPORATE & INSTITUTIONAL BANKING ━━━
    {"id": "corp_inet_banking", "name": "Corporate Internet Banking", "category": "corporate_banking",
     "asset_type": "web_server", "default_port": 443, "criticality": "critical",
     "description": "Bulk payments, payroll, vendor management, multi-level authorization",
     "scan_profile": "full", "compliance": ["pci_dss", "rbi_cyber", "sox"]},

    {"id": "treasury_portal", "name": "Treasury Management System", "category": "corporate_banking",
     "asset_type": "web_server", "default_port": 443, "criticality": "critical",
     "description": "Forex dealing, money market operations, liquidity management",
     "scan_profile": "full", "compliance": ["rbi_cyber", "sox", "basel_iii"]},

    {"id": "trade_finance", "name": "Trade Finance Portal", "category": "corporate_banking",
     "asset_type": "web_server", "default_port": 443, "criticality": "critical",
     "description": "LC, BG, documentary collection, supply chain finance",
     "scan_profile": "full", "compliance": ["swift_csp", "rbi_cyber", "icc"]},

    {"id": "cash_mgmt", "name": "Cash Management System", "category": "corporate_banking",
     "asset_type": "web_server", "default_port": 443, "criticality": "critical",
     "description": "Collections, payments, pooling, sweeping, virtual accounts",
     "scan_profile": "full", "compliance": ["pci_dss", "rbi_cyber"]},

    {"id": "escrow_portal", "name": "Escrow Account Management", "category": "corporate_banking",
     "asset_type": "web_server", "default_port": 443, "criticality": "high",
     "description": "Real estate escrow, project finance escrow management",
     "scan_profile": "full", "compliance": ["rera", "rbi_cyber"]},

    {"id": "supply_chain_finance", "name": "Supply Chain Finance Platform", "category": "corporate_banking",
     "asset_type": "web_server", "default_port": 443, "criticality": "high",
     "description": "Invoice discounting, reverse factoring, dealer financing",
     "scan_profile": "full", "compliance": ["pci_dss", "rbi_cyber"]},

    {"id": "fx_portal", "name": "Forex Trading Portal", "category": "corporate_banking",
     "asset_type": "web_server", "default_port": 443, "criticality": "critical",
     "description": "FX spot, forwards, swaps, options trading for corporates",
     "scan_profile": "full", "compliance": ["rbi_cyber", "fema"]},

    # ━━━ PAYMENT & TRANSACTION SYSTEMS ━━━
    {"id": "payment_gateway", "name": "Payment Gateway", "category": "payment_systems",
     "asset_type": "api", "default_port": 443, "criticality": "critical",
     "description": "Card payment processing, 3D Secure, tokenization",
     "scan_profile": "api_full", "compliance": ["pci_dss", "pci_3ds", "emvco"]},

    {"id": "upi_gateway", "name": "UPI Payment Gateway", "category": "payment_systems",
     "asset_type": "api", "default_port": 443, "criticality": "critical",
     "description": "Unified Payments Interface processing, collect/pay requests",
     "scan_profile": "api_full", "compliance": ["npci", "rbi_cyber", "pci_dss"]},

    {"id": "rtgs_neft", "name": "RTGS/NEFT/IMPS Gateway", "category": "payment_systems",
     "asset_type": "system", "default_port": 443, "criticality": "critical",
     "description": "Real-time gross settlement, national electronic funds transfer",
     "scan_profile": "full", "compliance": ["rbi_cyber", "pci_dss"]},

    {"id": "swift_gateway", "name": "SWIFT Alliance Gateway", "category": "payment_systems",
     "asset_type": "system", "default_port": 443, "criticality": "critical",
     "description": "SWIFT messaging for international payments, MT/MX messages",
     "scan_profile": "full", "compliance": ["swift_csp", "rbi_cyber", "fatf"]},

    {"id": "card_mgmt_system", "name": "Card Management System", "category": "payment_systems",
     "asset_type": "system", "default_port": 443, "criticality": "critical",
     "description": "Card issuance, PIN management, hot-listing, limit management",
     "scan_profile": "full", "compliance": ["pci_dss", "pci_pin", "emvco"]},

    {"id": "pos_gateway", "name": "POS Terminal Gateway", "category": "payment_systems",
     "asset_type": "api", "default_port": 443, "criticality": "critical",
     "description": "Point of sale terminal communication, EMV chip processing",
     "scan_profile": "api_full", "compliance": ["pci_dss", "pci_pts", "emvco"]},

    {"id": "atm_switch", "name": "ATM Switch & Network", "category": "payment_systems",
     "asset_type": "system", "default_port": 443, "criticality": "critical",
     "description": "ATM transaction routing, interchange, cash management",
     "scan_profile": "full", "compliance": ["pci_dss", "pci_pin"]},

    {"id": "qr_payment", "name": "QR Code Payment System", "category": "payment_systems",
     "asset_type": "api", "default_port": 443, "criticality": "high",
     "description": "Bharat QR, UPI QR, dynamic QR generation and processing",
     "scan_profile": "api_full", "compliance": ["npci", "emvco", "pci_dss"]},

    {"id": "ach_clearing", "name": "ACH / Clearing House Interface", "category": "payment_systems",
     "asset_type": "system", "default_port": 443, "criticality": "critical",
     "description": "Automated Clearing House, ECS, NACH batch processing",
     "scan_profile": "full", "compliance": ["rbi_cyber", "npci"]},

    {"id": "cross_border_payment", "name": "Cross-Border Payment Hub", "category": "payment_systems",
     "asset_type": "api", "default_port": 443, "criticality": "critical",
     "description": "International payment routing, SWIFT gpi, correspondent banking",
     "scan_profile": "full", "compliance": ["swift_csp", "fatf", "ofac"]},

    {"id": "iso20022_gateway", "name": "ISO 20022 Message Gateway", "category": "payment_systems",
     "asset_type": "api", "default_port": 443, "criticality": "critical",
     "description": "ISO 20022 XML messaging for payments, securities, trade",
     "scan_profile": "api_full", "compliance": ["swift_csp", "rbi_cyber"]},

    {"id": "bnpl_platform", "name": "Buy Now Pay Later Platform", "category": "payment_systems",
     "asset_type": "api", "default_port": 443, "criticality": "high",
     "description": "BNPL checkout integration, credit decisioning, EMI conversion",
     "scan_profile": "api_full", "compliance": ["rbi_digital_lending", "pci_dss"]},

    # ━━━ CAPITAL MARKETS & TRADING ━━━
    {"id": "trading_platform", "name": "Online Trading Platform", "category": "capital_markets",
     "asset_type": "web_server", "default_port": 443, "criticality": "critical",
     "description": "Equity, derivatives, commodity trading with real-time market data",
     "scan_profile": "full", "compliance": ["sebi", "pci_dss"]},

    {"id": "algo_trading", "name": "Algorithmic Trading Engine", "category": "capital_markets",
     "asset_type": "api", "default_port": 443, "criticality": "critical",
     "description": "High-frequency trading APIs, co-location services, DMA",
     "scan_profile": "api_full", "compliance": ["sebi", "fix_protocol"]},

    {"id": "fix_gateway", "name": "FIX Protocol Gateway", "category": "capital_markets",
     "asset_type": "system", "default_port": 443, "criticality": "critical",
     "description": "Financial Information eXchange protocol for order routing",
     "scan_profile": "full", "compliance": ["fix_protocol", "sebi"]},

    {"id": "custody_portal", "name": "Custody & Settlement Portal", "category": "capital_markets",
     "asset_type": "web_server", "default_port": 443, "criticality": "critical",
     "description": "Securities custody, settlement, corporate actions processing",
     "scan_profile": "full", "compliance": ["sebi", "swift_csp"]},

    {"id": "market_data_feed", "name": "Market Data Feed Service", "category": "capital_markets",
     "asset_type": "api", "default_port": 443, "criticality": "high",
     "description": "Real-time and historical market data distribution",
     "scan_profile": "api_full", "compliance": ["sebi"]},

    # ━━━ RISK, COMPLIANCE & REGULATORY ━━━
    {"id": "aml_system", "name": "Anti-Money Laundering System", "category": "risk_compliance",
     "asset_type": "web_server", "default_port": 443, "criticality": "critical",
     "description": "Transaction monitoring, STR filing, sanctions screening",
     "scan_profile": "full", "compliance": ["fatf", "rbi_kyc", "ofac", "fiu"]},

    {"id": "kyc_portal", "name": "KYC / CKYC Portal", "category": "risk_compliance",
     "asset_type": "web_server", "default_port": 443, "criticality": "critical",
     "description": "Know Your Customer, central KYC registry, re-KYC management",
     "scan_profile": "full", "compliance": ["rbi_kyc", "fatf", "gdpr"]},

    {"id": "fraud_detection", "name": "Fraud Detection & Prevention", "category": "risk_compliance",
     "asset_type": "system", "default_port": 443, "criticality": "critical",
     "description": "Real-time fraud analytics, device fingerprinting, behavioral biometrics",
     "scan_profile": "full", "compliance": ["pci_dss", "rbi_cyber"]},

    {"id": "regulatory_reporting", "name": "Regulatory Reporting Portal", "category": "risk_compliance",
     "asset_type": "web_server", "default_port": 443, "criticality": "high",
     "description": "RBI/SEBI/IRDAI reporting, XBRL filings, statutory returns",
     "scan_profile": "full", "compliance": ["rbi_cyber", "sox"]},

    {"id": "sanctions_screening", "name": "Sanctions Screening System", "category": "risk_compliance",
     "asset_type": "system", "default_port": 443, "criticality": "critical",
     "description": "OFAC, UN, EU sanctions list screening for all transactions",
     "scan_profile": "full", "compliance": ["ofac", "fatf", "un_sanctions"]},

    {"id": "credit_bureau", "name": "Credit Bureau Interface", "category": "risk_compliance",
     "asset_type": "api", "default_port": 443, "criticality": "high",
     "description": "CIBIL, Experian, Equifax, CRIF credit score integration",
     "scan_profile": "api_full", "compliance": ["rbi_cyber", "gdpr"]},

    {"id": "risk_engine", "name": "Enterprise Risk Management", "category": "risk_compliance",
     "asset_type": "web_server", "default_port": 443, "criticality": "high",
     "description": "Credit risk, market risk, operational risk dashboards",
     "scan_profile": "full", "compliance": ["basel_iii", "rbi_cyber"]},

    {"id": "stress_testing", "name": "Stress Testing Platform", "category": "risk_compliance",
     "asset_type": "web_server", "default_port": 443, "criticality": "high",
     "description": "Scenario analysis, ICAAP, ILAAP stress testing",
     "scan_profile": "full", "compliance": ["basel_iii", "rbi_cyber"]},

    # ━━━ CORE BANKING SYSTEMS ━━━
    {"id": "cbs_web", "name": "Core Banking System (Web)", "category": "core_banking",
     "asset_type": "web_server", "default_port": 443, "criticality": "critical",
     "description": "Finacle, T24, Flexcube, BaNCS core banking web interface",
     "scan_profile": "full", "compliance": ["rbi_cyber", "pci_dss", "sox"]},

    {"id": "cbs_api", "name": "Core Banking API Layer", "category": "core_banking",
     "asset_type": "api", "default_port": 443, "criticality": "critical",
     "description": "Core banking REST/SOAP APIs for channel integration",
     "scan_profile": "api_full", "compliance": ["rbi_cyber", "pci_dss"]},

    {"id": "los_system", "name": "Loan Origination System", "category": "core_banking",
     "asset_type": "web_server", "default_port": 443, "criticality": "high",
     "description": "Loan processing, credit appraisal, disbursement workflow",
     "scan_profile": "full", "compliance": ["rbi_cyber", "rbi_digital_lending"]},

    {"id": "dms_portal", "name": "Document Management System", "category": "core_banking",
     "asset_type": "web_server", "default_port": 443, "criticality": "medium",
     "description": "Digitized document storage, retrieval, workflow management",
     "scan_profile": "full", "compliance": ["rbi_cyber", "gdpr"]},

    {"id": "gl_system", "name": "General Ledger System", "category": "core_banking",
     "asset_type": "web_server", "default_port": 443, "criticality": "critical",
     "description": "Accounting, P&L, balance sheet, trial balance",
     "scan_profile": "full", "compliance": ["sox", "rbi_cyber"]},

    {"id": "mis_portal", "name": "Management Information System", "category": "core_banking",
     "asset_type": "web_server", "default_port": 443, "criticality": "high",
     "description": "Business analytics, performance dashboards, branch MIS",
     "scan_profile": "full", "compliance": ["rbi_cyber"]},

    # ━━━ DIGITAL CHANNELS & APIs ━━━
    {"id": "open_banking_api", "name": "Open Banking API Gateway", "category": "digital_channels",
     "asset_type": "api", "default_port": 443, "criticality": "critical",
     "description": "PSD2/Account Aggregator compliant APIs for TPPs",
     "scan_profile": "api_full", "compliance": ["psd2", "rbi_aa", "gdpr", "owasp_api"]},

    {"id": "account_aggregator", "name": "Account Aggregator (AA) Portal", "category": "digital_channels",
     "asset_type": "api", "default_port": 443, "criticality": "critical",
     "description": "RBI Account Aggregator framework FIP/FIU interface",
     "scan_profile": "api_full", "compliance": ["rbi_aa", "gdpr"]},

    {"id": "mobile_wallet", "name": "Mobile Wallet Platform", "category": "digital_channels",
     "asset_type": "api", "default_port": 443, "criticality": "critical",
     "description": "Prepaid wallet, P2P transfer, merchant payments",
     "scan_profile": "api_full", "compliance": ["rbi_ppi", "pci_dss"]},

    {"id": "chatbot_api", "name": "AI Banking Chatbot", "category": "digital_channels",
     "asset_type": "api", "default_port": 443, "criticality": "medium",
     "description": "Conversational AI for customer service, account queries",
     "scan_profile": "api_full", "compliance": ["rbi_cyber", "gdpr"]},

    {"id": "whatsapp_banking", "name": "WhatsApp Banking API", "category": "digital_channels",
     "asset_type": "api", "default_port": 443, "criticality": "high",
     "description": "WhatsApp Business API integration for banking services",
     "scan_profile": "api_full", "compliance": ["rbi_cyber", "gdpr"]},

    {"id": "video_kyc", "name": "Video KYC Platform", "category": "digital_channels",
     "asset_type": "web_server", "default_port": 443, "criticality": "high",
     "description": "Live video verification for remote customer onboarding",
     "scan_profile": "full", "compliance": ["rbi_kyc", "gdpr"]},

    {"id": "baas_platform", "name": "Banking-as-a-Service Platform", "category": "digital_channels",
     "asset_type": "api", "default_port": 443, "criticality": "critical",
     "description": "Embedded banking APIs for partners — accounts, cards, loans",
     "scan_profile": "api_full", "compliance": ["rbi_cyber", "pci_dss", "owasp_api"]},

    {"id": "api_marketplace", "name": "API Developer Portal", "category": "digital_channels",
     "asset_type": "web_server", "default_port": 443, "criticality": "medium",
     "description": "Developer documentation, sandbox, API key management",
     "scan_profile": "full", "compliance": ["owasp_api"]},

    # ━━━ INSURANCE & WEALTH ━━━
    {"id": "life_insurance", "name": "Life Insurance Portal", "category": "insurance",
     "asset_type": "web_server", "default_port": 443, "criticality": "high",
     "description": "Policy purchase, premium payment, claim filing",
     "scan_profile": "full", "compliance": ["irdai", "pci_dss"]},

    {"id": "general_insurance", "name": "General Insurance Portal", "category": "insurance",
     "asset_type": "web_server", "default_port": 443, "criticality": "high",
     "description": "Motor, health, travel, property insurance",
     "scan_profile": "full", "compliance": ["irdai", "pci_dss"]},

    {"id": "wealth_mgmt", "name": "Wealth Management Platform", "category": "insurance",
     "asset_type": "web_server", "default_port": 443, "criticality": "high",
     "description": "Portfolio management, advisory, HNI client dashboards",
     "scan_profile": "full", "compliance": ["sebi", "pci_dss"]},

    {"id": "robo_advisor", "name": "Robo-Advisory Platform", "category": "insurance",
     "asset_type": "api", "default_port": 443, "criticality": "medium",
     "description": "AI-driven investment advisory, auto-rebalancing",
     "scan_profile": "api_full", "compliance": ["sebi"]},

    # ━━━ BANKING INFRASTRUCTURE ━━━
    {"id": "hsm_interface", "name": "Hardware Security Module Interface", "category": "infrastructure",
     "asset_type": "system", "default_port": 443, "criticality": "critical",
     "description": "HSM management for PIN, key, certificate operations",
     "scan_profile": "full", "compliance": ["pci_dss", "pci_pin", "fips_140"]},

    {"id": "pki_portal", "name": "PKI / Certificate Authority", "category": "infrastructure",
     "asset_type": "web_server", "default_port": 443, "criticality": "critical",
     "description": "Internal CA, certificate lifecycle management",
     "scan_profile": "full", "compliance": ["rbi_cyber", "nist_pqc"]},

    {"id": "siem_portal", "name": "SIEM / SOC Dashboard", "category": "infrastructure",
     "asset_type": "web_server", "default_port": 443, "criticality": "critical",
     "description": "Security event monitoring, incident response, log analysis",
     "scan_profile": "full", "compliance": ["rbi_cyber", "sox"]},

    {"id": "iam_portal", "name": "Identity & Access Management", "category": "infrastructure",
     "asset_type": "web_server", "default_port": 443, "criticality": "critical",
     "description": "SSO, MFA, privileged access management, directory services",
     "scan_profile": "full", "compliance": ["rbi_cyber", "sox", "gdpr"]},

    {"id": "vpn_gateway", "name": "VPN Gateway (TLS-based)", "category": "infrastructure",
     "asset_type": "vpn", "default_port": 443, "criticality": "critical",
     "description": "SSL/TLS VPN for remote employee and branch connectivity",
     "scan_profile": "full", "compliance": ["rbi_cyber", "nist_pqc"]},

    {"id": "email_gateway", "name": "Email Security Gateway", "category": "infrastructure",
     "asset_type": "system", "default_port": 587, "criticality": "high",
     "description": "SMTP/SMTPS, email encryption, DLP, anti-phishing",
     "scan_profile": "full", "compliance": ["rbi_cyber"]},

    {"id": "waf_portal", "name": "Web Application Firewall", "category": "infrastructure",
     "asset_type": "system", "default_port": 443, "criticality": "critical",
     "description": "WAF management, rule configuration, DDoS protection",
     "scan_profile": "full", "compliance": ["rbi_cyber", "pci_dss"]},

    {"id": "backup_portal", "name": "Backup & DR Management", "category": "infrastructure",
     "asset_type": "web_server", "default_port": 443, "criticality": "high",
     "description": "Backup scheduling, DR drills, RPO/RTO monitoring",
     "scan_profile": "full", "compliance": ["rbi_cyber", "rbi_bcp"]},

    {"id": "endpoint_mgmt", "name": "Endpoint Management Console", "category": "infrastructure",
     "asset_type": "web_server", "default_port": 443, "criticality": "high",
     "description": "MDM, endpoint detection & response, patch management",
     "scan_profile": "full", "compliance": ["rbi_cyber"]},

    {"id": "network_mgmt", "name": "Network Management System", "category": "infrastructure",
     "asset_type": "web_server", "default_port": 443, "criticality": "high",
     "description": "Network monitoring, configuration, SNMP management",
     "scan_profile": "full", "compliance": ["rbi_cyber"]},

    # ━━━ FINTECH & NEO-BANKING ━━━
    {"id": "neobank_app", "name": "Neo-Bank Application", "category": "fintech",
     "asset_type": "api", "default_port": 443, "criticality": "critical",
     "description": "Digital-only bank APIs, zero-balance accounts, instant cards",
     "scan_profile": "api_full", "compliance": ["rbi_cyber", "pci_dss"]},

    {"id": "p2p_lending", "name": "P2P Lending Platform", "category": "fintech",
     "asset_type": "web_server", "default_port": 443, "criticality": "high",
     "description": "Peer-to-peer lending marketplace, borrower-lender matching",
     "scan_profile": "full", "compliance": ["rbi_p2p", "rbi_digital_lending"]},

    {"id": "crypto_exchange", "name": "Crypto Exchange / Custody", "category": "fintech",
     "asset_type": "web_server", "default_port": 443, "criticality": "critical",
     "description": "Cryptocurrency trading, wallet, custody services",
     "scan_profile": "full", "compliance": ["fatf", "fiu"]},

    {"id": "cbdc_gateway", "name": "CBDC / Digital Currency Gateway", "category": "fintech",
     "asset_type": "api", "default_port": 443, "criticality": "critical",
     "description": "Central Bank Digital Currency — e-Rupee issuance and settlement",
     "scan_profile": "api_full", "compliance": ["rbi_cyber", "nist_pqc"]},

    {"id": "embedded_finance", "name": "Embedded Finance APIs", "category": "fintech",
     "asset_type": "api", "default_port": 443, "criticality": "high",
     "description": "Lending, insurance, investments embedded in partner apps",
     "scan_profile": "api_full", "compliance": ["rbi_cyber", "rbi_digital_lending"]},

    {"id": "regtech_platform", "name": "RegTech Compliance Platform", "category": "fintech",
     "asset_type": "web_server", "default_port": 443, "criticality": "high",
     "description": "Automated regulatory compliance monitoring and reporting",
     "scan_profile": "full", "compliance": ["rbi_cyber", "sox"]},

    {"id": "suptech_portal", "name": "SupTech / Supervisory Portal", "category": "fintech",
     "asset_type": "web_server", "default_port": 443, "criticality": "high",
     "description": "Supervisory technology for central bank oversight",
     "scan_profile": "full", "compliance": ["rbi_cyber"]},

    # ━━━ INTERNATIONAL BANKING SYSTEMS ━━━
    {"id": "correspondent_banking", "name": "Correspondent Banking Portal", "category": "payment_systems",
     "asset_type": "web_server", "default_port": 443, "criticality": "critical",
     "description": "Vostro/Nostro account management, correspondent messaging",
     "scan_profile": "full", "compliance": ["swift_csp", "fatf", "ofac"]},

    {"id": "ebics_gateway", "name": "EBICS Gateway (Europe)", "category": "payment_systems",
     "asset_type": "system", "default_port": 443, "criticality": "critical",
     "description": "Electronic Banking Internet Communication Standard for EU banks",
     "scan_profile": "full", "compliance": ["psd2", "gdpr"]},

    {"id": "sepa_gateway", "name": "SEPA Payment Gateway", "category": "payment_systems",
     "asset_type": "api", "default_port": 443, "criticality": "critical",
     "description": "Single Euro Payments Area credit transfers and direct debits",
     "scan_profile": "api_full", "compliance": ["psd2", "gdpr"]},

    {"id": "fedwire", "name": "Fedwire / FedACH Interface", "category": "payment_systems",
     "asset_type": "system", "default_port": 443, "criticality": "critical",
     "description": "US Federal Reserve payment systems interface",
     "scan_profile": "full", "compliance": ["ffiec", "sox"]},

    {"id": "faster_payments", "name": "Faster Payments Service (UK)", "category": "payment_systems",
     "asset_type": "api", "default_port": 443, "criticality": "critical",
     "description": "UK real-time payments, Confirmation of Payee",
     "scan_profile": "api_full", "compliance": ["psd2", "gdpr", "fca"]},

    {"id": "pix_gateway", "name": "PIX Instant Payment (Brazil)", "category": "payment_systems",
     "asset_type": "api", "default_port": 443, "criticality": "critical",
     "description": "Brazilian Central Bank instant payment system",
     "scan_profile": "api_full", "compliance": ["bcb", "lgpd"]},

    {"id": "wechat_alipay", "name": "WeChat/Alipay Integration", "category": "payment_systems",
     "asset_type": "api", "default_port": 443, "criticality": "high",
     "description": "Chinese mobile payment platform integration",
     "scan_profile": "api_full", "compliance": ["pboc"]},
]


# ─────────────────────────── COMPLIANCE FRAMEWORKS ───────────────────────────

COMPLIANCE_FRAMEWORKS = {
    "pci_dss": {
        "name": "PCI DSS v4.0",
        "full_name": "Payment Card Industry Data Security Standard",
        "jurisdiction": "Global",
        "category": "Payment Security",
        "tls_requirements": {
            "min_version": "TLSv1.2",
            "required_ciphers": ["AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305"],
            "forbidden_ciphers": ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"],
            "require_pfs": True,
            "min_key_size": 2048,
            "require_hsts": True,
        },
        "checks": [
            {"id": "pci_2.2.7", "title": "Strong cryptography for non-console admin access", "severity": "critical"},
            {"id": "pci_4.1", "title": "Strong cryptography to safeguard cardholder data in transit", "severity": "critical"},
            {"id": "pci_4.2", "title": "PAN unreadable during transmission", "severity": "critical"},
            {"id": "pci_6.5", "title": "Address common coding vulnerabilities", "severity": "high"},
            {"id": "pci_8.3", "title": "Multi-factor authentication for all access", "severity": "high"},
        ],
    },
    "rbi_cyber": {
        "name": "RBI Cybersecurity Framework",
        "full_name": "Reserve Bank of India Cybersecurity Framework for Banks",
        "jurisdiction": "India",
        "category": "Banking Regulation",
        "tls_requirements": {
            "min_version": "TLSv1.2",
            "require_pfs": True,
            "min_key_size": 2048,
            "require_hsts": True,
        },
        "checks": [
            {"id": "rbi_1", "title": "Board-approved cyber security policy", "severity": "high"},
            {"id": "rbi_2", "title": "Cyber Security Operations Center (C-SOC)", "severity": "high"},
            {"id": "rbi_3", "title": "Network segmentation", "severity": "medium"},
            {"id": "rbi_4", "title": "Encryption of data at rest and in transit", "severity": "critical"},
            {"id": "rbi_5", "title": "Advanced real-time threat detection", "severity": "high"},
            {"id": "rbi_6", "title": "Vulnerability assessment and penetration testing", "severity": "high"},
        ],
    },
    "swift_csp": {
        "name": "SWIFT CSP v2024",
        "full_name": "SWIFT Customer Security Programme",
        "jurisdiction": "Global",
        "category": "Payment Messaging",
        "tls_requirements": {
            "min_version": "TLSv1.2",
            "require_pfs": True,
            "min_key_size": 2048,
        },
        "checks": [
            {"id": "swift_1.1", "title": "Restrict Internet Access", "severity": "critical"},
            {"id": "swift_1.2", "title": "Segregation of critical systems", "severity": "critical"},
            {"id": "swift_2.1", "title": "Internal data flow security", "severity": "high"},
            {"id": "swift_2.2", "title": "Security updates", "severity": "high"},
            {"id": "swift_4.1", "title": "Password policy", "severity": "medium"},
            {"id": "swift_5.1", "title": "Logical access control", "severity": "critical"},
        ],
    },
    "gdpr": {
        "name": "GDPR",
        "full_name": "General Data Protection Regulation",
        "jurisdiction": "European Union",
        "category": "Data Privacy",
        "tls_requirements": {"min_version": "TLSv1.2", "require_pfs": True},
        "checks": [
            {"id": "gdpr_32", "title": "Security of processing — encryption", "severity": "critical"},
            {"id": "gdpr_25", "title": "Data protection by design and default", "severity": "high"},
        ],
    },
    "sox": {
        "name": "SOX",
        "full_name": "Sarbanes-Oxley Act",
        "jurisdiction": "United States",
        "category": "Financial Reporting",
        "tls_requirements": {"min_version": "TLSv1.2"},
        "checks": [
            {"id": "sox_302", "title": "Corporate responsibility for financial reports", "severity": "high"},
            {"id": "sox_404", "title": "Internal controls assessment", "severity": "high"},
        ],
    },
    "basel_iii": {
        "name": "Basel III",
        "full_name": "Basel III Framework for Operational Risk",
        "jurisdiction": "Global",
        "category": "Banking Regulation",
        "tls_requirements": {"min_version": "TLSv1.2"},
        "checks": [
            {"id": "basel_or1", "title": "Operational risk management", "severity": "high"},
            {"id": "basel_or2", "title": "IT risk governance", "severity": "medium"},
        ],
    },
    "psd2": {
        "name": "PSD2",
        "full_name": "Payment Services Directive 2",
        "jurisdiction": "European Union",
        "category": "Open Banking",
        "tls_requirements": {"min_version": "TLSv1.2", "require_pfs": True, "require_mtls": True},
        "checks": [
            {"id": "psd2_sca", "title": "Strong Customer Authentication", "severity": "critical"},
            {"id": "psd2_api", "title": "Dedicated API interface for TPPs", "severity": "high"},
        ],
    },
    "nist_pqc": {
        "name": "NIST PQC",
        "full_name": "NIST Post-Quantum Cryptography Standards",
        "jurisdiction": "Global",
        "category": "Cryptographic Standards",
        "tls_requirements": {
            "recommended_kex": ["ML-KEM-768", "ML-KEM-1024", "X25519MLKEM768"],
            "recommended_sig": ["ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-256s"],
        },
        "checks": [
            {"id": "fips_203", "title": "ML-KEM key encapsulation support", "severity": "high"},
            {"id": "fips_204", "title": "ML-DSA digital signature support", "severity": "high"},
            {"id": "fips_205", "title": "SLH-DSA hash-based signature support", "severity": "medium"},
        ],
    },
    "ffiec": {
        "name": "FFIEC",
        "full_name": "Federal Financial Institutions Examination Council",
        "jurisdiction": "United States",
        "category": "Banking Regulation",
        "tls_requirements": {"min_version": "TLSv1.2", "require_pfs": True},
        "checks": [
            {"id": "ffiec_auth", "title": "Authentication and access control", "severity": "critical"},
            {"id": "ffiec_audit", "title": "Audit and logging", "severity": "high"},
        ],
    },
    "fatf": {
        "name": "FATF",
        "full_name": "Financial Action Task Force Recommendations",
        "jurisdiction": "Global",
        "category": "AML/CFT",
        "tls_requirements": {},
        "checks": [
            {"id": "fatf_10", "title": "Customer due diligence", "severity": "critical"},
            {"id": "fatf_20", "title": "Suspicious transaction reporting", "severity": "critical"},
        ],
    },
    "owasp_api": {
        "name": "OWASP API Top 10",
        "full_name": "OWASP API Security Top 10 - 2023",
        "jurisdiction": "Global",
        "category": "API Security",
        "tls_requirements": {"min_version": "TLSv1.2", "require_pfs": True},
        "checks": [
            {"id": "api1", "title": "Broken Object Level Authorization", "severity": "critical"},
            {"id": "api2", "title": "Broken Authentication", "severity": "critical"},
            {"id": "api3", "title": "Broken Object Property Level Authorization", "severity": "high"},
            {"id": "api4", "title": "Unrestricted Resource Consumption", "severity": "medium"},
            {"id": "api5", "title": "Broken Function Level Authorization", "severity": "critical"},
        ],
    },
}


def get_templates_by_category(category=None):
    """Get banking templates, optionally filtered by category."""
    if category:
        return [t for t in BANKING_TEMPLATES if t["category"] == category]
    return BANKING_TEMPLATES


def get_template_by_id(template_id):
    """Get a specific template by ID."""
    for t in BANKING_TEMPLATES:
        if t["id"] == template_id:
            return t
    return None


def get_compliance_framework(framework_id):
    """Get compliance framework details."""
    return COMPLIANCE_FRAMEWORKS.get(framework_id)


def check_tls_compliance(scan_data, framework_id):
    """Check scan results against a compliance framework's TLS requirements."""
    framework = COMPLIANCE_FRAMEWORKS.get(framework_id)
    if not framework:
        return {"error": f"Unknown framework: {framework_id}"}

    req = framework.get("tls_requirements", {})
    results = []
    tls_info = scan_data.get("tls_info", {})
    ciphers = scan_data.get("ciphers", [])
    cert = scan_data.get("certificate", {})

    # TLS version check
    min_ver = req.get("min_version")
    if min_ver:
        version = tls_info.get("version", "")
        ver_order = {"SSLv2": 0, "SSLv3": 1, "TLSv1": 2, "TLSv1.0": 2, "TLSv1.1": 3, "TLSv1.2": 4, "TLSv1.3": 5}
        actual = ver_order.get(version, 0)
        required = ver_order.get(min_ver.replace("+", ""), 4)
        results.append({
            "check": f"TLS version >= {min_ver}",
            "status": "pass" if actual >= required else "fail",
            "actual": version,
            "required": min_ver,
        })

    # PFS check
    if req.get("require_pfs"):
        kex = scan_data.get("key_exchange", {}).get("algorithm", "")
        has_pfs = kex in ("ECDHE", "DHE", "ML-KEM")
        results.append({
            "check": "Perfect Forward Secrecy",
            "status": "pass" if has_pfs else "fail",
            "actual": kex,
        })

    # Key size
    min_key = req.get("min_key_size")
    if min_key and cert:
        actual_key = cert.get("public_key_size", 0)
        results.append({
            "check": f"Key size >= {min_key} bits",
            "status": "pass" if actual_key >= min_key else "fail",
            "actual": actual_key,
            "required": min_key,
        })

    # Forbidden ciphers
    forbidden = req.get("forbidden_ciphers", [])
    if forbidden:
        bad = [c["cipher_suite"] for c in ciphers if any(f.upper() in c.get("cipher_suite", "").upper() for f in forbidden)]
        results.append({
            "check": "No forbidden cipher suites",
            "status": "fail" if bad else "pass",
            "violations": bad,
        })

    passed = sum(1 for r in results if r["status"] == "pass")
    total = len(results)

    return {
        "framework": framework_id,
        "framework_name": framework["name"],
        "results": results,
        "passed": passed,
        "total": total,
        "compliance_pct": round(passed / total * 100, 1) if total > 0 else 0,
        "compliant": passed == total,
    }
