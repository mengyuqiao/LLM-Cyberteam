import json
import re
import math
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
import openai
from abc import ABC, abstractmethod

@dataclass
class LLMResponse:
    """Standard response format for LLM operations"""
    operation: str
    success: bool
    result: Any
    confidence: float
    reasoning: str
    raw_response: str

class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers"""
    
    @abstractmethod
    def generate_response(self, prompt: str, temperature: float = 0.3, max_tokens: int = 2048) -> str:
        pass

class OpenAIProvider(BaseLLMProvider):
    """OpenAI GPT provider implementation"""
    
    def __init__(self, api_key: str, model: str = "gpt-4"):
        self.client = openai.OpenAI(api_key=api_key)
        self.model = model
    
    def generate_response(self, prompt: str, temperature: float = 0.3, max_tokens: int = 2048) -> str:
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=temperature,
                max_tokens=max_tokens
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error: {str(e)}"

class MockLLMProvider(BaseLLMProvider):
    """Mock LLM provider for testing without API calls"""
    
    def generate_response(self, prompt: str, temperature: float = 0.3, max_tokens: int = 2048) -> str:
        # Return mock responses based on operation type
        if "Named Entity Recognition" in prompt:
            return '''```json
{
    "threat_actors": [
        {"entity": "APT29", "category": "threat_actor", "confidence": 0.95},
        {"entity": "Cozy Bear", "category": "threat_actor", "confidence": 0.85}
    ],
    "malware": [
        {"entity": "trojan", "category": "malware_type", "confidence": 0.8}
    ],
    "vulnerabilities": [
        {"entity": "CVE-2024-21345", "category": "vulnerability", "confidence": 0.98}
    ],
    "infrastructure": [
        {"entity": "185.100.87.21", "category": "ip_address", "confidence": 0.9},
        {"entity": "evil-domain.com", "category": "domain", "confidence": 0.85}
    ]
}
```'''
        elif "Regex Pattern Matching" in prompt:
            return '''```json
{
    "ip_addresses": ["185.100.87.21", "192.168.1.1"],
    "domains": ["evil-domain.com", "malicious-site.org"],
    "file_hashes": {
        "md5": ["a1b2c3d4e5f6789012345678901234567890abcdef"],
        "sha1": [],
        "sha256": ["abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"]
    },
    "urls": ["http://malicious-site.org/payload"],
    "email_addresses": ["attacker@evil-domain.com"],
    "timestamps": ["2024-01-15 14:30:22"]
}
```'''
        else:
            return "Mock LLM response for testing purposes."

class LLMCyberTeamOperations:
    """LLM-powered implementation of CYBERTEAM operations using detailed prompts"""
    
    def __init__(self, llm_provider: BaseLLMProvider, prompts_file: str = "cyberteam_prompts.json"):
        self.llm = llm_provider
        self.prompts = self._load_prompts(prompts_file)
    
    def _load_prompts(self, prompts_file: str) -> Dict[str, Any]:
        """Load prompts from file, with fallback to embedded prompts"""
        try:
            with open(prompts_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Fallback to embedded prompts if file not found
            return self._get_embedded_prompts()
    
    def _get_embedded_prompts(self) -> Dict[str, Any]:
        """Embedded prompts as fallback"""
        return {
            "ner_threat_attribution": {
                "system_prompt": "You are a cybersecurity threat intelligence assistant specialized in named entity recognition for threat attribution.",
                "user_template": "Extract and categorize cybersecurity entities from the following text: {text}",
                "output_format": "JSON with threat_actors, malware, vulnerabilities, infrastructure arrays"
            }
            # Additional prompts would be loaded from external file
        }
    
    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """Extract and parse JSON from LLM response"""
        # Try to find JSON in response
        json_match = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass
        
        # Try to parse entire response as JSON
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return {"error": "Could not parse JSON response", "raw": response}
    
    def ner_threat_attribution(self, text: str) -> LLMResponse:
        """LLM-powered Named Entity Recognition for threat attribution"""
        
        prompt = f"""You are a cybersecurity threat intelligence assistant specialized in named entity recognition. Your task is to extract and categorize all named entities relevant to threat attribution from the provided text.

INSTRUCTIONS:
Extract all cybersecurity-relevant named entities and classify them into these categories:

1. THREAT ACTORS: Individual hackers, groups, APT groups, state-sponsored actors
   - Examples: APT29, Lazarus Group, FIN7, Carbanak, specific hacker aliases
   - Include confidence score (0.0-1.0)

2. MALWARE/TOOLS: Names of malicious software, exploits, hacking tools
   - Examples: Specific malware names, trojan families, ransomware variants
   - Include generic types like "trojan", "ransomware" if mentioned

3. VULNERABILITIES: CVE identifiers, specific security flaws
   - Examples: CVE-2024-1234, buffer overflow vulnerabilities
   - Include both CVE numbers and descriptive vulnerability types

4. INFRASTRUCTURE: IPs, domains, URLs, file hashes, email addresses
   - Examples: Command & control servers, malicious domains, file hashes
   - Distinguish between different infrastructure types

ANALYSIS FOCUS:
- Answer "Who is responsible for the attack?"
- Answer "How was the attack carried out?"
- Look for attribution indicators (language, TTPs, infrastructure reuse)
- Identify attack methods and tools used

OUTPUT FORMAT:
Return results as a JSON object with this exact structure:
```json
{{
    "threat_actors": [
        {{"entity": "entity_name", "category": "threat_actor", "confidence": 0.95, "context": "brief context"}}
    ],
    "malware": [
        {{"entity": "malware_name", "category": "malware_type", "confidence": 0.85, "context": "brief context"}}
    ],
    "vulnerabilities": [
        {{"entity": "CVE-2024-1234", "category": "vulnerability", "confidence": 0.98, "context": "brief context"}}
    ],
    "infrastructure": [
        {{"entity": "192.168.1.1", "category": "ip_address", "confidence": 0.9, "context": "brief context"}}
    ]
}}
```

INPUT TEXT:
{text}

Extract all relevant entities with high precision. If uncertain about an entity, include it with lower confidence score. Provide brief context for each entity explaining why it's relevant to threat attribution."""

        try:
            response = self.llm.generate_response(prompt, temperature=0.2)
            parsed_result = self._parse_json_response(response)
            
            if "error" in parsed_result:
                return LLMResponse(
                    operation="ner_threat_attribution",
                    success=False,
                    result=None,
                    confidence=0.0,
                    reasoning=parsed_result["error"],
                    raw_response=response
                )
            
            return LLMResponse(
                operation="ner_threat_attribution",
                success=True,
                result=parsed_result,
                confidence=0.9,
                reasoning="Successfully extracted cybersecurity entities",
                raw_response=response
            )
            
        except Exception as e:
            return LLMResponse(
                operation="ner_threat_attribution",
                success=False,
                result=None,
                confidence=0.0,
                reasoning=f"Error during LLM processing: {str(e)}",
                raw_response=""
            )
    
    def rex_extract_indicators(self, text: str) -> LLMResponse:
        """LLM-powered regex pattern matching for indicator extraction"""
        
        prompt = f"""You are a cybersecurity parsing assistant specialized in extracting structured threat indicators from raw incident reports and logs.

TASK: Parse the following document and extract ALL instances of these indicator types using pattern recognition:

INDICATOR TYPES TO EXTRACT:

1. IP ADDRESSES:
   - IPv4 format: xxx.xxx.xxx.xxx (0-255 for each octet)
   - Include private and public ranges
   - Examples: 192.168.1.1, 10.0.0.1, 185.100.87.21

2. FILE HASHES:
   - MD5: 32 hexadecimal characters
   - SHA1: 40 hexadecimal characters  
   - SHA256: 64 hexadecimal characters
   - Case insensitive matching

3. DOMAIN NAMES:
   - Valid domain format with TLD
   - Include subdomains
   - Examples: evil-domain.com, sub.malicious-site.org
   - Exclude obvious false positives

4. URLs:
   - Complete HTTP/HTTPS URLs
   - Include path and parameters if present
   - Examples: https://malicious-site.org/payload?id=123

5. EMAIL ADDRESSES:
   - Valid email format: user@domain.tld
   - Include potential attacker emails

6. TIMESTAMPS:
   - Various formats: YYYY-MM-DD HH:MM:SS, MM/DD/YYYY HH:MM:SS, ISO format
   - Include timezone if present

EXTRACTION RULES:
- Extract ALL matches, even if they appear multiple times
- Maintain exact formatting as found in text
- Do not modify or normalize the extracted values
- Group by type for easy analysis
- Include confidence assessment for ambiguous matches

OUTPUT FORMAT:
Return results as JSON with this exact structure:
```json
{{
    "ip_addresses": ["192.168.1.1", "10.0.0.1"],
    "domains": ["evil-domain.com", "malicious-site.org"],
    "file_hashes": {{
        "md5": ["a1b2c3d4e5f6789012345678901234567890abcdef"],
        "sha1": ["da39a3ee5e6b4b0d3255bfef95601890afd80709"],
        "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    }},
    "urls": ["https://evil-domain.com/payload"],
    "email_addresses": ["attacker@evil-domain.com"],
    "timestamps": ["2024-01-15 14:30:22", "01/15/2024 02:30:22 PM"]
}}
```

INPUT TEXT:
{text}

Extract all indicators with maximum precision. If a value could match multiple patterns, include it in the most specific category."""

        try:
            response = self.llm.generate_response(prompt, temperature=0.1)
            parsed_result = self._parse_json_response(response)
            
            return LLMResponse(
                operation="rex_extract_indicators",
                success="error" not in parsed_result,
                result=parsed_result,
                confidence=0.95 if "error" not in parsed_result else 0.0,
                reasoning="Successfully extracted threat indicators" if "error" not in parsed_result else parsed_result.get("error", "Unknown error"),
                raw_response=response
            )
            
        except Exception as e:
            return LLMResponse(
                operation="rex_extract_indicators",
                success=False,
                result=None,
                confidence=0.0,
                reasoning=f"Error during indicator extraction: {str(e)}",
                raw_response=""
            )
    
    def sum_threat_report(self, text: str, max_sentences: int = 4) -> LLMResponse:
        """LLM-powered threat report summarization"""
        
        prompt = f"""You are a cybersecurity analyst assistant. Your task is to summarize the following threat report in exactly {max_sentences} sentences, preserving the most critical intelligence.

SUMMARIZATION REQUIREMENTS:

CONTENT PRIORITIES (in order of importance):
1. Attack vector and initial access method
2. Threat actor identification (if known)
3. Affected systems and timeline
4. Key indicators of compromise (IOCs)
5. Tactics, techniques, and procedures (TTPs)
6. Impact and consequences

ESSENTIAL ELEMENTS TO PRESERVE:
- Specific dates and times when available
- CVE numbers and vulnerability details
- Threat actor names (APT groups, aliases)
- Critical file hashes, IPs, or domains
- Attack methods and tools used
- Target organizations or sectors

WRITING STYLE:
- Use active voice and precise technical language
- Avoid generic phrases like "threat actors" without specifics
- Include quantitative data when available
- Maintain professional cybersecurity terminology
- Each sentence should convey unique, actionable intelligence

EXCLUSIONS:
- Remove redundant information
- Eliminate speculative language
- Skip generic security advice
- Omit background context unless critical

OUTPUT FORMAT:
Return a JSON object with this structure:
```json
{{
    "summary": "Four sentences of executive summary here. Each sentence should contain specific, actionable threat intelligence. Include dates, names, and technical details where available. Focus on attribution, attack methods, and key indicators.",
    "key_elements": {{
        "threat_actors": ["APT29", "Lazarus Group"],
        "attack_vectors": ["phishing", "exploitation"],
        "affected_systems": ["Windows", "Linux servers"],
        "timeline": "2024-01-15 to 2024-01-20",
        "critical_iocs": ["185.100.87.21", "CVE-2024-1234"]
    }},
    "confidence": 0.9,
    "intelligence_value": "high"
}}
```

INPUT TEXT:
{text}

Generate a concise, intelligence-focused summary that preserves maximum actionable value in {max_sentences} sentences."""

        try:
            response = self.llm.generate_response(prompt, temperature=0.3)
            parsed_result = self._parse_json_response(response)
            
            return LLMResponse(
                operation="sum_threat_report",
                success="error" not in parsed_result,
                result=parsed_result,
                confidence=parsed_result.get("confidence", 0.8) if "error" not in parsed_result else 0.0,
                reasoning="Successfully generated threat intelligence summary" if "error" not in parsed_result else parsed_result.get("error", "Unknown error"),
                raw_response=response
            )
            
        except Exception as e:
            return LLMResponse(
                operation="sum_threat_report",
                success=False,
                result=None,
                confidence=0.0,
                reasoning=f"Error during summarization: {str(e)}",
                raw_response=""
            )
    
    def sim_geocultural_match(self, text1: str, text2: str) -> LLMResponse:
        """LLM-powered geocultural similarity matching"""
        
        prompt = f"""You are a cybersecurity assistant that specializes in determining whether two geolocation or cultural indicators refer to the same threat origin. Use advanced contextual reasoning and cybersecurity domain knowledge to make this determination.

ANALYSIS TASK:
Determine if these two phrases describe the same group, region, or geopolitical background in a cyber threat context:

PHRASE 1: "{text1}"
PHRASE 2: "{text2}"

EVALUATION CRITERIA:

1. GEOGRAPHIC EQUIVALENCE:
   - Do both descriptions point to the same geographic region?
   - Consider historical and political boundaries
   - Account for regional groupings (Eastern Europe, Middle East, etc.)

2. CULTURAL/LINGUISTIC CONNECTIONS:
   - Do they refer to the same cultural or linguistic group?
   - Consider language families and cultural ties
   - Account for diaspora and cultural spread

3. GEOPOLITICAL CONTEXT:
   - Are they used interchangeably in threat intelligence?
   - Do they refer to the same state or political entity?
   - Consider historical alliances and political groupings

4. THREAT INTELLIGENCE CONVENTION:
   - How are these terms typically used in cybersecurity reporting?
   - Do security researchers treat them as equivalent?
   - Consider common attribution patterns

EXAMPLES OF EQUIVALENCE:
- "Russian" ≈ "Eastern European" (in many threat contexts)
- "Chinese" ≈ "East Asian" (when referring to state-sponsored groups)
- "North Korean" ≈ "DPRK"
- "Iranian" ≈ "Persian" ≈ "Middle Eastern" (context-dependent)

ANALYSIS QUESTIONS:
1. Do both descriptions point to the same cultural, linguistic, or geopolitical region?
2. Are these expressions used interchangeably in threat intelligence contexts?
3. Would a cybersecurity analyst consider these equivalent for attribution purposes?
4. Do they reference the same state, region, or cultural group?

OUTPUT FORMAT:
```json
{{
    "match": true/false,
    "confidence": 0.85,
    "justification": "Both terms refer to Russian-speaking threat actors commonly associated with Eastern European cybercriminal groups. In threat intelligence, 'Russian-affiliated' and 'Eastern European' are frequently used interchangeably when discussing similar threat actor profiles and operational characteristics.",
    "geographic_analysis": "Both refer to the Eastern European region with strong Russian cultural influence",
    "threat_intel_context": "These terms are commonly used as synonyms in APT and cybercriminal reporting",
    "equivalence_factors": ["geographic_overlap", "cultural_similarity", "threat_intel_convention"]
}}
```

Provide detailed reasoning for your decision, considering the specific context of cybersecurity threat attribution."""

        try:
            response = self.llm.generate_response(prompt, temperature=0.4)
            parsed_result = self._parse_json_response(response)
            
            return LLMResponse(
                operation="sim_geocultural_match",
                success="error" not in parsed_result,
                result=parsed_result,
                confidence=parsed_result.get("confidence", 0.7) if "error" not in parsed_result else 0.0,
                reasoning="Successfully analyzed geocultural similarity" if "error" not in parsed_result else parsed_result.get("error", "Unknown error"),
                raw_response=response
            )
            
        except Exception as e:
            return LLMResponse(
                operation="sim_geocultural_match",
                success=False,
                result=None,
                confidence=0.0,
                reasoning=f"Error during similarity analysis: {str(e)}",
                raw_response=""
            )
    
    def map_threat_knowledge(self, text: str) -> LLMResponse:
        """LLM-powered threat knowledge graph mapping"""
        
        prompt = f"""You are a cybersecurity knowledge graph assistant. Extract and relate key entities from the given threat report to form structured subject-predicate-object triples that represent threat intelligence relationships.

TASK: Analyze the threat report and extract meaningful relationships between cybersecurity entities.

ENTITY TYPES TO IDENTIFY:
- Threat actors (APT groups, individuals, aliases)
- Malware (families, variants, tools)
- Infrastructure (IPs, domains, URLs, servers)
- Vulnerabilities (CVEs, exploit types)
- Organizations (targets, victims, sectors)
- Techniques (MITRE ATT&CK techniques, TTPs)
- Campaigns (operation names, attack series)

RELATIONSHIP TYPES TO EXTRACT:

OPERATIONAL RELATIONSHIPS:
- "uses" - Actor uses tool/malware/technique
- "operates" - Actor operates infrastructure
- "targets" - Actor targets organization/sector
- "exploits" - Actor/malware exploits vulnerability
- "communicates_with" - Malware communicates with C2
- "drops" - Malware drops other malware
- "affects" - Vulnerability affects product/system

ATTRIBUTION RELATIONSHIPS:
- "attributed_to" - Attack attributed to actor
- "associated_with" - Entities linked by evidence
- "similar_to" - Entities showing similarities
- "part_of" - Entity part of larger campaign

TECHNICAL RELATIONSHIPS:
- "connects_to" - Network connections
- "hosts" - Infrastructure hosts resources
- "resolves_to" - Domain resolves to IP
- "contains" - File contains other elements

EXTRACTION GUIDELINES:
1. Focus on actionable intelligence relationships
2. Use specific entity names when available
3. Prefer concrete relationships over speculative ones
4. Include confidence scores based on evidence strength
5. Extract both direct and inferred relationships

OUTPUT FORMAT:
```json
{{
    "triples": [
        {{
            "subject": "APT29",
            "predicate": "uses",
            "object": "Cobalt Strike",
            "confidence": 0.9,
            "evidence": "Report states APT29 deployed Cobalt Strike beacons"
        }},
        {{
            "subject": "malware.exe",
            "predicate": "communicates_with", 
            "object": "185.100.87.21",
            "confidence": 0.95,
            "evidence": "Network analysis shows C2 communication"
        }}
    ],
    "entities_found": {{
        "threat_actors": ["APT29"],
        "malware": ["Cobalt Strike", "malware.exe"],
        "infrastructure": ["185.100.87.21"],
        "techniques": ["lateral_movement"]
    }},
    "relationship_summary": "Extracted 15 relationships showing APT29 campaign infrastructure and TTPs"
}}
```

INPUT TEXT:
{text}

Extract all meaningful cybersecurity relationships with supporting evidence. Focus on relationships that provide actionable threat intelligence."""

        try:
            response = self.llm.generate_response(prompt, temperature=0.3)
            parsed_result = self._parse_json_response(response)
            
            return LLMResponse(
                operation="map_threat_knowledge",
                success="error" not in parsed_result,
                result=parsed_result,
                confidence=0.85 if "error" not in parsed_result else 0.0,
                reasoning="Successfully extracted threat knowledge relationships" if "error" not in parsed_result else parsed_result.get("error", "Unknown error"),
                raw_response=response
            )
            
        except Exception as e:
            return LLMResponse(
                operation="map_threat_knowledge",
                success=False,
                result=None,
                confidence=0.0,
                reasoning=f"Error during knowledge mapping: {str(e)}",
                raw_response=""
            )
    
    def rag_query_threat_intel(self, query: str, sources: Optional[List[str]] = None) -> LLMResponse:
        """LLM-powered RAG query generation for threat intelligence"""
        
        if not sources:
            sources = ["mitre.org", "virustotal.com", "cisa.gov", "nvd.nist.gov", "mandiant.com"]
        
        prompt = f"""You are a cybersecurity assistant specialized in formulating precise search queries to retrieve current threat intelligence information.

QUERY ANALYSIS TASK:
Based on the topic: "{query}"

INSTRUCTIONS:
1. Analyze the query intent and identify the type of threat intelligence needed
2. Extract key search terms and entities
3. Determine the most relevant sources for this information
4. Generate optimized search queries for different intelligence platforms

QUERY TYPES TO IDENTIFY:
- THREAT ACTOR: Attribution, campaign analysis, TTP profiling
- MALWARE: Family analysis, IOC collection, behavioral analysis  
- VULNERABILITY: Exploit information, patch status, impact assessment
- CAMPAIGN: Attack correlation, timeline analysis, victim identification
- GENERAL: Multi-faceted threat landscape analysis

SOURCE OPTIMIZATION:
- MITRE ATT&CK: For TTP and technique information
- MITRE CVE: For vulnerability details
- VirusTotal: For malware analysis and IOCs
- CISA Advisories: For current threats and mitigations
- Mandiant/FireEye: For APT intelligence and attribution
- NVD: For vulnerability scoring and details

SEARCH STRATEGY:
1. Identify 3-5 most relevant search terms
2. Use boolean operators effectively (AND, OR, NOT)
3. Include site-specific searches for authoritative sources
4. Consider synonyms and alternative terminology
5. Balance specificity with comprehensiveness

OUTPUT FORMAT:
```json
{{
    "query_analysis": {{
        "intent": "threat_actor_attribution",
        "entities_identified": ["APT29", "phishing", "2024"],
        "information_needed": ["recent campaigns", "TTPs", "IOCs"],
        "urgency": "high"
    }},
    "optimized_queries": {{
        "primary": "APT29 phishing campaign 2024 indicators tools targets",
        "mitre_specific": "APT29 phishing site:attack.mitre.org",
        "virustotal_specific": "APT29 2024 site:virustotal.com",
        "general_web": "APT29 phishing 2024 IOCs TTPs (site:mandiant.com OR site:cisa.gov OR site:fireeye.com)"
    }},
    "search_terms": ["APT29", "phishing", "2024", "campaign", "indicators", "TTPs"],
    "expected_sources": ["mitre.org", "virustotal.com", "mandiant.com", "cisa.gov"],
    "query_complexity": "medium",
    "estimated_results": "50-200 relevant documents"
}}
```

SOURCE LIST: {sources}

Generate comprehensive search queries that will retrieve the most relevant and current threat intelligence for this query."""

        try:
            response = self.llm.generate_response(prompt, temperature=0.4)
            parsed_result = self._parse_json_response(response)
            
            return LLMResponse(
                operation="rag_query_threat_intel",
                success="error" not in parsed_result,
                result=parsed_result,
                confidence=0.8 if "error" not in parsed_result else 0.0,
                reasoning="Successfully generated threat intelligence queries" if "error" not in parsed_result else parsed_result.get("error", "Unknown error"),
                raw_response=response
            )
            
        except Exception as e:
            return LLMResponse(
                operation="rag_query_threat_intel",
                success=False,
                result=None,
                confidence=0.0,
                reasoning=f"Error during query generation: {str(e)}",
                raw_response=""
            )
    
    def spa_extract_technique_span(self, text: str) -> LLMResponse:
        """LLM-powered text span localization for attack techniques"""
        
        prompt = f"""You are a cybersecurity span identification assistant specialized in extracting precise text spans that describe attack techniques and methods.

TASK: Locate and extract text spans that directly describe how attackers compromised systems or executed their attacks.

SPAN TYPES TO IDENTIFY:

1. INITIAL ACCESS TECHNIQUES:
   - Phishing methods and delivery mechanisms
   - Exploitation of vulnerabilities
   - Drive-by downloads and watering holes
   - Supply chain compromises

2. EXECUTION TECHNIQUES:
   - Command line execution
   - Script execution (PowerShell, VBS, etc.)
   - Malware deployment and activation
   - Living-off-the-land techniques

3. PERSISTENCE TECHNIQUES:
   - Registry modifications
   - Scheduled tasks and services
   - Backdoor installation
   - Account manipulation

4. PRIVILEGE ESCALATION:
   - Exploitation of local vulnerabilities
   - Token manipulation
   - Process injection techniques

5. DEFENSE EVASION:
   - Obfuscation methods
   - Anti-analysis techniques
   - Process hollowing
   - File masquerading

6. CREDENTIAL ACCESS:
   - Password dumping
   - Keylogging
   - Credential harvesting

7. DISCOVERY & LATERAL MOVEMENT:
   - Network reconnaissance
   - Remote services exploitation
   - Internal pivoting methods

8. COLLECTION & EXFILTRATION:
   - Data gathering techniques
   - Compression and archiving
   - Data transfer methods

EXTRACTION CRITERIA:
- Extract complete sentences or phrases that describe techniques
- Include enough context to understand the method
- Focus on actionable technical details
- Classify by MITRE ATT&CK technique categories
- Provide character positions for precise localization

OUTPUT FORMAT:
```json
{{
    "extracted_spans": [
        {{
            "span": "The attackers used spear-phishing emails with malicious PDF attachments to gain initial access to the target network",
            "start_position": 145,
            "end_position": 248,
            "technique_category": "initial_access",
            "mitre_technique": "T1566.001",
            "confidence": 0.95,
            "context": "Describes spear-phishing as initial access vector"
        }},
        {{
            "span": "PowerShell scripts were executed to download additional payloads from the command and control server",
            "start_position": 312,
            "end_position": 398,
            "technique_category": "execution",
            "mitre_technique": "T1059.001",
            "confidence": 0.9,
            "context": "PowerShell-based payload download"
        }}
    ],
    "technique_summary": {{
        "total_spans": 2,
        "categories_found": ["initial_access", "execution"],
        "attack_flow": ["phishing", "powershell_execution", "c2_communication"]
    }},
    "span_quality": "high"
}}
```

INPUT TEXT:
{text}

Extract all text spans that describe attack techniques with precise character positions. Focus on spans that provide clear, actionable descriptions of how attacks were carried out."""

        try:
            response = self.llm.generate_response(prompt, temperature=0.2)
            parsed_result = self._parse_json_response(response)
            
            return LLMResponse(
                operation="spa_extract_technique_span",
                success="error" not in parsed_result,
                result=parsed_result,
                confidence=0.85 if "error" not in parsed_result else 0.0,
                reasoning="Successfully extracted attack technique spans" if "error" not in parsed_result else parsed_result.get("error", "Unknown error"),
                raw_response=response
            )
            
        except Exception as e:
            return LLMResponse(
                operation="spa_extract_technique_span",
                success=False,
                result=None,
                confidence=0.0,
                reasoning=f"Error during span extraction: {str(e)}",
                raw_response=""
            )
    
    def cls_attack_vector(self, description: str) -> LLMResponse:
        """LLM-powered attack vector classification"""
        
        prompt = f"""You are a cybersecurity classification specialist. Analyze the given vulnerability or attack description and classify the attack vector according to CVSS v3.1 standards.

CLASSIFICATION TASK:
Analyze this description: "{description}"

ATTACK VECTOR CATEGORIES (CVSS v3.1):

1. NETWORK (AV:N):
   - Attack requires network access
   - Remotely exploitable vulnerabilities
   - Examples: Web application flaws, network protocol vulnerabilities
   - Indicators: "remote", "network", "HTTP", "TCP", "UDP", "web-based"

2. ADJACENT NETWORK (AV:A):
   - Attack limited to same shared physical/logical network
   - Requires local network access
   - Examples: ARP spoofing, wireless attacks, broadcast/multicast exploitation
   - Indicators: "wireless", "LAN", "Bluetooth", "adjacent", "local network"

3. LOCAL (AV:L):
   - Attack requires local access to target system
   - Physical or shell access needed
   - Examples: Privilege escalation, local file inclusion
   - Indicators: "local", "privilege escalation", "file system", "shell access"

4. PHYSICAL (AV:P):
   - Attack requires physical access to target
   - Direct hardware interaction needed
   - Examples: USB attacks, hardware tampering, console access
   - Indicators: "physical", "hardware", "USB", "console", "BIOS", "firmware"

CLASSIFICATION CRITERIA:
- Identify the MINIMUM level of access required for exploitation
- Consider the attack surface and entry points
- Evaluate the network positioning requirements
- Assess physical proximity needs

ANALYSIS FACTORS:
1. Access Requirements: What level of access does the attacker need?
2. Attack Surface: Where is the vulnerability exposed?
3. Network Position: What network access is required?
4. Proximity: How close must the attacker be to the target?

OUTPUT FORMAT:
```json
{{
    "classification": "network",
    "confidence": 0.85,
    "cvss_notation": "AV:N",
    "reasoning": "The vulnerability can be exploited remotely over a network connection without requiring local access or physical proximity to the target system.",
    "indicators_found": ["remote", "network", "HTTP"],
    "attack_surface": "network_exposed",
    "minimum_access_required": "network_connectivity",
    "alternative_classifications": [
        {{"type": "adjacent_network", "probability": 0.1, "reason": "Could potentially be local network only"}}
    ]
}}
```

Provide detailed reasoning for your classification decision, including specific text indicators that support your choice."""

        try:
            response = self.llm.generate_response(prompt, temperature=0.2)
            parsed_result = self._parse_json_response(response)
            
            return LLMResponse(
                operation="cls_attack_vector",
                success="error" not in parsed_result,
                result=parsed_result,
                confidence=parsed_result.get("confidence", 0.7) if "error" not in parsed_result else 0.0,
                reasoning="Successfully classified attack vector" if "error" not in parsed_result else parsed_result.get("error", "Unknown error"),
                raw_response=response
            )
            
        except Exception as e:
            return LLMResponse(
                operation="cls_attack_vector",
                success=False,
                result=None,
                confidence=0.0,
                reasoning=f"Error during classification: {str(e)}",
                raw_response=""
            )
    
    def math_cvss_score(self, 
                       confidentiality_impact: str,
                       integrity_impact: str,
                       availability_impact: str,
                       attack_vector: str = "network",
                       attack_complexity: str = "low", 
                       privileges_required: str = "none",
                       user_interaction: str = "none",
                       scope: str = "unchanged") -> LLMResponse:
        """LLM-powered CVSS score calculation"""
        
        prompt = f"""You are a cybersecurity scoring specialist expert in CVSS v3.1 calculations. Calculate the precise CVSS Base Score using the official CVSS v3.1 mathematical formulas.

CVSS v3.1 CALCULATION TASK:

INPUT METRICS:
- Confidentiality Impact: {confidentiality_impact}
- Integrity Impact: {integrity_impact} 
- Availability Impact: {availability_impact}
- Attack Vector: {attack_vector}
- Attack Complexity: {attack_complexity}
- Privileges Required: {privileges_required}
- User Interaction: {user_interaction}
- Scope: {scope}

CVSS v3.1 METRIC VALUES:

Attack Vector (AV):
- Network: 0.85
- Adjacent: 0.62  
- Local: 0.55
- Physical: 0.2

Attack Complexity (AC):
- Low: 0.77
- High: 0.44

Privileges Required (PR):
- None: 0.85
- Low: 0.68 (Scope Changed) / 0.62 (Scope Unchanged)
- High: 0.50 (Scope Changed) / 0.27 (Scope Unchanged)

User Interaction (UI):
- None: 0.85
- Required: 0.62

Confidentiality Impact (C):
- None: 0.0
- Low: 0.22
- High: 0.56

Integrity Impact (I):
- None: 0.0
- Low: 0.22  
- High: 0.56

Availability Impact (A):
- None: 0.0
- Low: 0.22
- High: 0.56

CALCULATION FORMULAS:

1. Impact Sub-score Base (ISCBase):
   ISCBase = 1 - ((1 - C) × (1 - I) × (1 - A))

2. Impact Sub-score:
   - If Scope = Unchanged: Impact = 6.42 × ISCBase
   - If Scope = Changed: Impact = 7.52 × (ISCBase - 0.029) - 3.25 × (ISCBase - 0.02)^15

3. Exploitability Sub-score:
   Exploitability = 8.22 × AV × AC × PR × UI

4. Base Score:
   - If Impact ≤ 0: Base Score = 0
   - If Scope = Unchanged: Base Score = Round Up(min(Impact + Exploitability, 10))
   - If Scope = Changed: Base Score = Round Up(min(1.08 × (Impact + Exploitability), 10))

5. Severity Rating:
   - 0.0: None
   - 0.1-3.9: Low
   - 4.0-6.9: Medium  
   - 7.0-8.9: High
   - 9.0-10.0: Critical

CALCULATION REQUIREMENTS:
- Use exact CVSS v3.1 formulas
- Round Base Score UP to one decimal place
- Show all intermediate calculations
- Verify against official CVSS calculator logic

OUTPUT FORMAT:
```json
{{
    "cvss_calculation": {{
        "base_score": 7.5,
        "severity": "High",
        "impact_subscore": 5.9,
        "exploitability_subscore": 3.9,
        "isc_base": 0.96
    }},
    "metric_values": {{
        "AV": 0.85,
        "AC": 0.77,
        "PR": 0.85,
        "UI": 0.85,
        "C": 0.56,
        "I": 0.56,
        "A": 0.56
    }},
    "calculation_steps": [
        "ISCBase = 1 - ((1-0.56) × (1-0.56) × (1-0.56)) = 0.96",
        "Impact = 6.42 × 0.96 = 5.9",
        "Exploitability = 8.22 × 0.85 × 0.77 × 0.85 × 0.85 = 3.9",
        "Base Score = Round Up(min(5.9 + 3.9, 10)) = 7.5"
    ],
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "confidence": 1.0
}}
```

Perform the complete CVSS v3.1 calculation with step-by-step mathematical operations."""

        try:
            response = self.llm.generate_response(prompt, temperature=0.1)
            parsed_result = self._parse_json_response(response)
            
            return LLMResponse(
                operation="math_cvss_score", 
                success="error" not in parsed_result,
                result=parsed_result,
                confidence=parsed_result.get("confidence", 0.95) if "error" not in parsed_result else 0.0,
                reasoning="Successfully calculated CVSS score" if "error" not in parsed_result else parsed_result.get("error", "Unknown error"),
                raw_response=response
            )
            
        except Exception as e:
            return LLMResponse(
                operation="math_cvss_score",
                success=False,
                result=None,
                confidence=0.0,
                reasoning=f"Error during CVSS calculation: {str(e)}",
                raw_response=""
            )

# Demonstration and testing functions
def demonstrate_llm_cyberteam_operations():
    """Demonstrate the LLM-powered CYBERTEAM operations"""
    
    # Initialize with mock provider for demonstration
    llm_provider = MockLLMProvider()
    cyber_ops = LLMCyberTeamOperations(llm_provider)
    
    # Sample threat report
    sample_text = """
    On December 10, 2024, APT29 (also known as Cozy Bear) launched a sophisticated 
    spear-phishing campaign targeting government organizations across Eastern Europe.
    The attack leveraged CVE-2024-21345, a zero-day vulnerability in Microsoft Exchange,
    to gain initial access to target networks. The malware payload communicates with
    C2 server at 185.100.87.21 and drops additional payloads from evil-domain.com.
    File hash a1b2c3d4e5f6789012345678901234567890abcdef was identified as part of 
    the campaign. The attackers used PowerShell scripts to execute lateral movement
    and establish persistence through registry modifications.
    """
    
    print("=== LLM-Powered CYBERTEAM Operations Demo ===\n")
    
    # Demonstrate each operation
    operations = [
        ("Named Entity Recognition", cyber_ops.ner_threat_attribution, sample_text),
        ("Indicator Extraction", cyber_ops.rex_extract_indicators, sample_text),
        ("Threat Report Summary", cyber_ops.sum_threat_report, sample_text),
        ("Geocultural Matching", cyber_ops.sim_geocultural_match, "Eastern European", "Russian-speaking"),
        ("Knowledge Mapping", cyber_ops.map_threat_knowledge, sample_text),
        ("RAG Query Generation", cyber_ops.rag_query_threat_intel, "APT29 recent campaigns 2024"),
        ("Technique Span Extraction", cyber_ops.spa_extract_technique_span, sample_text),
        ("Attack Vector Classification", cyber_ops.cls_attack_vector, "Remote network exploitation via HTTP"),
        ("CVSS Score Calculation", cyber_ops.math_cvss_score, "high", "high", "high", "network", "low")
    ]
    
    for i, (name, func, *args) in enumerate(operations, 1):
        print(f"{i}. {name}:")
        try:
            if len(args) == 1:
                result = func(args[0])
            elif len(args) == 2:
                result = func(args[0], args[1])
            else:
                result = func(*args)
            
            print(f"   Success: {result.success}")
            print(f"   Confidence: {result.confidence}")
            if result.success and result.result:
                if isinstance(result.result, dict):
                    # Pretty print first few keys
                    shown_keys = list(result.result.keys())[:3]
                    for key in shown_keys:
                        print(f"   {key}: {str(result.result[key])[:100]}...")
                else:
                    print(f"   Result: {str(result.result)[:100]}...")
            print()
            
        except Exception as e:
            print(f"   Error: {str(e)}\n")

if __name__ == "__main__":
    demonstrate_llm_cyberteam_operations()