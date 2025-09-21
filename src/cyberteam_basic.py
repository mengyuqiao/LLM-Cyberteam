import re
import json
import hashlib
import math
from typing import Dict, List, Tuple, Any, Optional, Union
from datetime import datetime
import requests
from dataclasses import dataclass
from sentence_transformers import SentenceTransformer
import numpy as np

@dataclass
class ThreatEntity:
    """Data class for threat entities"""
    entity: str
    category: str
    confidence: float

@dataclass
class CVSSScore:
    """Data class for CVSS scoring"""
    base_score: float
    impact_subscore: float
    exploitability_subscore: float
    severity: str

class CyberTeamOperations:
    """
    Implementation of CYBERTEAM function-guided operations for threat hunting
    """
    
    def __init__(self):
        # Initialize sentence transformer for similarity calculations
        try:
            self.sentence_model = SentenceTransformer('all-MiniLM-L6-v2')
        except:
            self.sentence_model = None
            print("Warning: Sentence transformer not available. Some functions may be limited.")
    
    # 1. NER (Named Entity Recognition)
    def ner_threat_attribution(self, text: str) -> Dict[str, List[ThreatEntity]]:
        """
        Extract cybersecurity-relevant named entities for threat attribution
        
        Args:
            text: Input cybersecurity text/report
            
        Returns:
            Dictionary of entity categories and extracted entities
        """
        entities = {
            "threat_actors": [],
            "malware": [],
            "vulnerabilities": [],
            "infrastructure": []
        }
        
        # Threat actor patterns
        apt_pattern = r'\b(?:APT[\-\s]?\d+|APT[A-Z]+\d*|Lazarus|Carbanak|FIN\d+|TA\d+)\b'
        actor_matches = re.finditer(apt_pattern, text, re.IGNORECASE)
        for match in actor_matches:
            entities["threat_actors"].append(
                ThreatEntity(match.group(), "threat_actor", 0.9)
            )
        
        # CVE pattern
        cve_pattern = r'\bCVE-\d{4}-\d{4,7}\b'
        cve_matches = re.finditer(cve_pattern, text, re.IGNORECASE)
        for match in cve_matches:
            entities["vulnerabilities"].append(
                ThreatEntity(match.group(), "vulnerability", 0.95)
            )
        
        # IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_matches = re.finditer(ip_pattern, text)
        for match in ip_matches:
            entities["infrastructure"].append(
                ThreatEntity(match.group(), "ip_address", 0.85)
            )
        
        # Domains
        domain_pattern = r'\b[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}\b'
        domain_matches = re.finditer(domain_pattern, text)
        for match in domain_matches:
            if not re.match(ip_pattern, match.group()):
                entities["infrastructure"].append(
                    ThreatEntity(match.group(), "domain", 0.8)
                )
        
        # Common malware names
        malware_keywords = ['trojan', 'ransomware', 'botnet', 'backdoor', 'rootkit', 
                           'keylogger', 'spyware', 'worm', 'virus']
        for keyword in malware_keywords:
            if keyword.lower() in text.lower():
                entities["malware"].append(
                    ThreatEntity(keyword, "malware_type", 0.7)
                )
        
        return entities
    
    # 2. REX (Regex Parsing)
    def rex_extract_indicators(self, text: str) -> Dict[str, List[str]]:
        """
        Extract structured threat indicators using regex patterns
        
        Args:
            text: Input text containing threat indicators
            
        Returns:
            Dictionary of indicator types and extracted values
        """
        indicators = {
            "ip_addresses": [],
            "domains": [],
            "file_hashes": {
                "md5": [],
                "sha1": [],
                "sha256": []
            },
            "urls": [],
            "email_addresses": [],
            "timestamps": []
        }
        
        # IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        indicators["ip_addresses"] = re.findall(ip_pattern, text)
        
        # Domains
        domain_pattern = r'\b[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}\b'
        indicators["domains"] = re.findall(domain_pattern, text)
        
        # File hashes
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        
        indicators["file_hashes"]["md5"] = re.findall(md5_pattern, text)
        indicators["file_hashes"]["sha1"] = re.findall(sha1_pattern, text)
        indicators["file_hashes"]["sha256"] = re.findall(sha256_pattern, text)
        
        # URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+[^\s<>"{}|\\^`\[\].,;:!?]'
        indicators["urls"] = re.findall(url_pattern, text)
        
        # Email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        indicators["email_addresses"] = re.findall(email_pattern, text)
        
        # Timestamps (various formats)
        timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',  # ISO format
            r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}',   # US format
            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'    # Standard format
        ]
        
        for pattern in timestamp_patterns:
            indicators["timestamps"].extend(re.findall(pattern, text))
        
        return indicators
    
    # 3. SUM (Summarization)
    def sum_threat_report(self, text: str, max_sentences: int = 4) -> str:
        """
        Generate concise summary of threat reports preserving key details
        
        Args:
            text: Full threat report text
            max_sentences: Maximum sentences in summary
            
        Returns:
            Summarized text
        """
        sentences = re.split(r'[.!?]+', text)
        sentences = [s.strip() for s in sentences if len(s.strip()) > 20]
        
        # Score sentences based on cybersecurity keywords
        cyber_keywords = [
            'attack', 'threat', 'malware', 'vulnerability', 'exploit', 
            'breach', 'compromise', 'incident', 'IOC', 'TTP', 'actor',
            'campaign', 'phishing', 'ransomware', 'backdoor', 'C2'
        ]
        
        sentence_scores = []
        for sentence in sentences:
            score = 0
            for keyword in cyber_keywords:
                score += sentence.lower().count(keyword.lower())
            
            # Boost score for sentences with specific indicators
            if re.search(r'CVE-\d{4}-\d{4,7}', sentence):
                score += 3
            if re.search(r'APT\d+|APT[A-Z]+', sentence):
                score += 3
            if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', sentence):
                score += 2
                
            sentence_scores.append((sentence, score))
        
        # Sort by score and take top sentences
        sentence_scores.sort(key=lambda x: x[1], reverse=True)
        top_sentences = [s[0] for s in sentence_scores[:max_sentences]]
        
        return '. '.join(top_sentences) + '.'
    
    # 4. SIM (Text Similarity Matching)
    def sim_geocultural_match(self, text1: str, text2: str) -> Dict[str, Union[bool, float, str]]:
        """
        Determine semantic similarity between geocultural threat indicators
        
        Args:
            text1, text2: Texts to compare for similarity
            
        Returns:
            Dictionary with match decision, confidence, and justification
        """
        # Normalize texts
        text1_norm = text1.lower().strip()
        text2_norm = text2.lower().strip()
        
        # Exact match
        if text1_norm == text2_norm:
            return {
                "match": True,
                "confidence": 1.0,
                "justification": "Exact textual match"
            }
        
        # Geographic/cultural equivalence mappings
        geo_mappings = {
            "russia": ["russian", "russian-speaking", "eastern european", "ex-soviet"],
            "china": ["chinese", "sino", "east asian", "prc"],
            "north korea": ["dprk", "north korean", "korean"],
            "iran": ["iranian", "persian", "middle eastern"],
            "eastern europe": ["russian", "slavic", "ex-soviet", "post-soviet"]
        }
        
        # Check for geographic equivalence
        for region, aliases in geo_mappings.items():
            if (text1_norm in aliases or region in text1_norm) and \
               (text2_norm in aliases or region in text2_norm):
                return {
                    "match": True,
                    "confidence": 0.85,
                    "justification": f"Both refer to {region} region/culture"
                }
        
        # Use sentence transformer if available
        if self.sentence_model:
            embeddings = self.sentence_model.encode([text1, text2])
            similarity = np.dot(embeddings[0], embeddings[1]) / \
                        (np.linalg.norm(embeddings[0]) * np.linalg.norm(embeddings[1]))
            
            if similarity > 0.7:
                return {
                    "match": True,
                    "confidence": float(similarity),
                    "justification": "High semantic similarity detected"
                }
        
        # Fuzzy string matching fallback
        common_words = set(text1_norm.split()) & set(text2_norm.split())
        if len(common_words) > 0:
            jaccard_similarity = len(common_words) / \
                                len(set(text1_norm.split()) | set(text2_norm.split()))
            
            if jaccard_similarity > 0.3:
                return {
                    "match": True,
                    "confidence": jaccard_similarity,
                    "justification": f"Shared terms: {', '.join(common_words)}"
                }
        
        return {
            "match": False,
            "confidence": 0.0,
            "justification": "No significant similarity detected"
        }
    
    # 5. MAP (Text Mapping)
    def map_threat_knowledge(self, text: str) -> List[Tuple[str, str, str]]:
        """
        Extract knowledge graph triples from threat reports
        
        Args:
            text: Threat report text
            
        Returns:
            List of (subject, predicate, object) triples
        """
        triples = []
        
        # Extract entities first
        entities = self.ner_threat_attribution(text)
        
        # Simple pattern-based relation extraction
        sentences = re.split(r'[.!?]+', text)
        
        for sentence in sentences:
            sentence = sentence.strip()
            if len(sentence) < 10:
                continue
            
            # Pattern: Actor uses/operates Tool
            uses_pattern = r'(APT\d+|[A-Z]+\d+)\s+(?:uses?|operates?|employs?)\s+([a-zA-Z0-9\-_]+)'
            matches = re.finditer(uses_pattern, sentence, re.IGNORECASE)
            for match in matches:
                triples.append((match.group(1), "uses", match.group(2)))
            
            # Pattern: Actor targets Organization/Sector
            targets_pattern = r'(APT\d+|[A-Z]+\d+)\s+(?:targets?|attacks?)\s+([a-zA-Z\s]+(?:sector|industry|organization))'
            matches = re.finditer(targets_pattern, sentence, re.IGNORECASE)
            for match in matches:
                triples.append((match.group(1), "targets", match.group(2).strip()))
            
            # Pattern: Malware communicates with C2
            c2_pattern = r'([a-zA-Z0-9\-_]+)\s+(?:communicates?|connects?)\s+(?:to|with)\s+(\d+\.\d+\.\d+\.\d+|[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})'
            matches = re.finditer(c2_pattern, sentence, re.IGNORECASE)
            for match in matches:
                triples.append((match.group(1), "communicates_with", match.group(2)))
            
            # Pattern: CVE affects Product
            cve_affects_pattern = r'(CVE-\d{4}-\d{4,7})\s+(?:affects?|impacts?)\s+([a-zA-Z0-9\s\-]+)'
            matches = re.finditer(cve_affects_pattern, sentence, re.IGNORECASE)
            for match in matches:
                triples.append((match.group(1), "affects", match.group(2).strip()))
        
        return triples
    
    # 6. RAG (Retrieval-Augmented Generation)
    def rag_query_threat_intel(self, query: str, sources: List[str] = None) -> Dict[str, Any]:
        """
        Generate structured query for threat intelligence retrieval
        
        Args:
            query: Search query about threats
            sources: Optional list of preferred sources
            
        Returns:
            Structured query and mock retrieved information
        """
        # Parse query intent
        query_lower = query.lower()
        
        # Identify query type
        if any(term in query_lower for term in ['apt', 'actor', 'group']):
            query_type = "threat_actor"
        elif any(term in query_lower for term in ['malware', 'trojan', 'ransomware']):
            query_type = "malware"
        elif any(term in query_lower for term in ['cve', 'vulnerability', 'exploit']):
            query_type = "vulnerability"
        else:
            query_type = "general"
        
        # Generate search terms
        search_terms = []
        
        # Extract key entities
        entities = self.ner_threat_attribution(query)
        for category, entity_list in entities.items():
            search_terms.extend([e.entity for e in entity_list])
        
        # Add context terms based on query type
        if query_type == "threat_actor":
            search_terms.extend(["campaign", "TTP", "attribution", "indicators"])
        elif query_type == "malware":
            search_terms.extend(["IOC", "behavior", "analysis", "family"])
        elif query_type == "vulnerability":
            search_terms.extend(["patch", "exploit", "mitigation", "CVSS"])
        
        # Construct search query
        if not sources:
            sources = ["mitre.org", "virustotal.com", "cisa.gov", "nvd.nist.gov"]
        
        site_queries = " OR ".join([f"site:{source}" for source in sources])
        final_query = f"{' '.join(search_terms[:5])} ({site_queries})"
        
        # Mock retrieval results (in real implementation, would query actual APIs)
        mock_results = {
            "query": final_query,
            "query_type": query_type,
            "search_terms": search_terms,
            "sources_queried": sources,
            "retrieved_passages": [
                "Mock threat intelligence passage 1 relevant to query",
                "Mock threat intelligence passage 2 with IOCs and TTPs"
            ]
        }
        
        return mock_results
    
    # 7. SPA (Text Span Localization)
    def spa_extract_technique_span(self, text: str) -> Dict[str, Any]:
        """
        Extract text spans describing attack techniques
        
        Args:
            text: Input text containing technique descriptions
            
        Returns:
            Dictionary with extracted spans and positions
        """
        technique_patterns = [
            r'[^.]*(?:phishing|spear.?phishing)[^.]*\.',
            r'[^.]*(?:lateral movement|privilege escalation)[^.]*\.',
            r'[^.]*(?:command and control|C2|exfiltration)[^.]*\.',
            r'[^.]*(?:persistence|backdoor|rootkit)[^.]*\.',
            r'[^.]*(?:credential access|credential theft|password)[^.]*\.'
        ]
        
        extracted_spans = []
        
        for pattern in technique_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE | re.DOTALL)
            for match in matches:
                span = match.group().strip()
                if len(span) > 20:  # Filter out very short matches
                    extracted_spans.append({
                        "span": span,
                        "start": match.start(),
                        "end": match.end(),
                        "technique_type": self._classify_technique(span)
                    })
        
        # Remove duplicates and sort by position
        unique_spans = []
        seen_spans = set()
        for span_info in sorted(extracted_spans, key=lambda x: x['start']):
            if span_info['span'] not in seen_spans:
                unique_spans.append(span_info)
                seen_spans.add(span_info['span'])
        
        return {
            "extracted_spans": unique_spans,
            "total_spans": len(unique_spans)
        }
    
    def _classify_technique(self, span: str) -> str:
        """Helper to classify technique type from span"""
        span_lower = span.lower()
        if 'phishing' in span_lower:
            return "initial_access"
        elif any(term in span_lower for term in ['lateral', 'movement', 'privilege', 'escalation']):
            return "privilege_escalation"
        elif any(term in span_lower for term in ['persistence', 'backdoor']):
            return "persistence"
        elif any(term in span_lower for term in ['credential', 'password']):
            return "credential_access"
        elif any(term in span_lower for term in ['c2', 'command', 'control', 'exfiltration']):
            return "command_control"
        else:
            return "unknown"
    
    # 8. CLS (Classification)
    def cls_attack_vector(self, description: str) -> Dict[str, Any]:
        """
        Classify attack vectors from vulnerability descriptions
        
        Args:
            description: Vulnerability or attack description
            
        Returns:
            Classification result with confidence
        """
        desc_lower = description.lower()
        
        # Classification rules
        if any(term in desc_lower for term in ['network', 'remote', 'tcp', 'udp', 'http', 'https']):
            return {
                "classification": "network",
                "confidence": 0.85,
                "reasoning": "Contains network-related terms"
            }
        elif any(term in desc_lower for term in ['local', 'privilege', 'file system', 'registry']):
            return {
                "classification": "local",
                "confidence": 0.8,
                "reasoning": "Contains local system terms"
            }
        elif any(term in desc_lower for term in ['physical', 'usb', 'hardware', 'bios']):
            return {
                "classification": "physical",
                "confidence": 0.9,
                "reasoning": "Contains physical access terms"
            }
        elif any(term in desc_lower for term in ['adjacent', 'bluetooth', 'wifi', 'wireless']):
            return {
                "classification": "adjacent_network",
                "confidence": 0.75,
                "reasoning": "Contains adjacent network terms"
            }
        else:
            return {
                "classification": "unknown",
                "confidence": 0.3,
                "reasoning": "No clear attack vector indicators"
            }
    
    # 9. MATH (Mathematical Calculation)
    def math_cvss_score(self, 
                       confidentiality_impact: float,
                       integrity_impact: float, 
                       availability_impact: float,
                       attack_vector: str = "network",
                       attack_complexity: str = "low",
                       privileges_required: str = "none",
                       user_interaction: str = "none",
                       scope: str = "unchanged") -> CVSSScore:
        """
        Calculate CVSS v3.1 Base Score
        
        Args:
            confidentiality_impact: Impact on confidentiality (0.0-1.0)
            integrity_impact: Impact on integrity (0.0-1.0) 
            availability_impact: Impact on availability (0.0-1.0)
            attack_vector: Attack vector type
            attack_complexity: Attack complexity level
            privileges_required: Required privileges
            user_interaction: User interaction requirement
            scope: Scope of impact
            
        Returns:
            CVSSScore object with calculated values
        """
        # Map categorical values to numeric scores
        av_scores = {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.2}
        ac_scores = {"low": 0.77, "high": 0.44}
        pr_scores = {
            "none": 0.85,
            "low": 0.68 if scope == "changed" else 0.62,
            "high": 0.50 if scope == "changed" else 0.27
        }
        ui_scores = {"none": 0.85, "required": 0.62}
        
        # Get numeric values
        av = av_scores.get(attack_vector.lower(), 0.85)
        ac = ac_scores.get(attack_complexity.lower(), 0.77)
        pr = pr_scores.get(privileges_required.lower(), 0.85)
        ui = ui_scores.get(user_interaction.lower(), 0.85)
        
        # Calculate Impact Sub-score
        isc_base = 1 - ((1 - confidentiality_impact) * 
                       (1 - integrity_impact) * 
                       (1 - availability_impact))
        
        if scope.lower() == "unchanged":
            impact_subscore = 6.42 * isc_base
        else:
            impact_subscore = 7.52 * (isc_base - 0.029) - 3.25 * pow(isc_base - 0.02, 15)
        
        # Calculate Exploitability Sub-score
        exploitability_subscore = 8.22 * av * ac * pr * ui
        
        # Calculate Base Score
        if impact_subscore <= 0:
            base_score = 0.0
        elif scope.lower() == "unchanged":
            base_score = min(impact_subscore + exploitability_subscore, 10.0)
        else:
            base_score = min(1.08 * (impact_subscore + exploitability_subscore), 10.0)
        
        # Round up to one decimal place
        base_score = math.ceil(base_score * 10) / 10
        
        # Determine severity
        if base_score == 0.0:
            severity = "None"
        elif base_score <= 3.9:
            severity = "Low"
        elif base_score <= 6.9:
            severity = "Medium"
        elif base_score <= 8.9:
            severity = "High"
        else:
            severity = "Critical"
        
        return CVSSScore(
            base_score=base_score,
            impact_subscore=round(impact_subscore, 1),
            exploitability_subscore=round(exploitability_subscore, 1),
            severity=severity
        )

# Example usage and testing functions
def demonstrate_cyberteam_operations():
    """Demonstrate the CYBERTEAM operations with sample data"""
    
    cyber_ops = CyberTeamOperations()
    
    # Sample threat report
    sample_text = """
    APT29 conducted a sophisticated phishing campaign targeting government organizations.
    The attack leveraged CVE-2024-21345 to gain initial access. The malware communicates
    with C2 server at 185.100.87.21 and drops additional payloads. File hash 
    a1b2c3d4e5f6789012345678901234567890abcdef was identified as part of the campaign.
    The attack shows characteristics of Eastern European threat actors.
    """
    
    print("=== CYBERTEAM Function-Guided Operations Demo ===\n")
    
    # 1. NER
    print("1. Named Entity Recognition:")
    entities = cyber_ops.ner_threat_attribution(sample_text)
    for category, entity_list in entities.items():
        if entity_list:
            print(f"  {category}: {[e.entity for e in entity_list]}")
    
    # 2. REX
    print("\n2. Regex Parsing:")
    indicators = cyber_ops.rex_extract_indicators(sample_text)
    for ioc_type, values in indicators.items():
        if values and not isinstance(values, dict):
            print(f"  {ioc_type}: {values}")
        elif isinstance(values, dict):
            for subtype, subvalues in values.items():
                if subvalues:
                    print(f"  {ioc_type}_{subtype}: {subvalues}")
    
    # 3. SUM
    print("\n3. Summarization:")
    summary = cyber_ops.sum_threat_report(sample_text)
    print(f"  Summary: {summary}")
    
    # 4. SIM
    print("\n4. Similarity Matching:")
    sim_result = cyber_ops.sim_geocultural_match("Eastern European", "Russian-speaking")
    print(f"  Match: {sim_result}")
    
    # 5. MAP
    print("\n5. Knowledge Mapping:")
    triples = cyber_ops.map_threat_knowledge(sample_text)
    for triple in triples:
        print(f"  {triple[0]} -> {triple[1]} -> {triple[2]}")
    
    # 6. SPA
    print("\n6. Span Extraction:")
    spans = cyber_ops.spa_extract_technique_span(sample_text)
    for span_info in spans["extracted_spans"]:
        print(f"  {span_info['technique_type']}: {span_info['span'][:60]}...")
    
    # 7. CLS
    print("\n7. Classification:")
    classification = cyber_ops.cls_attack_vector("Remote network exploitation via HTTP")
    print(f"  Attack Vector: {classification}")
    
    # 8. MATH
    print("\n8. CVSS Calculation:")
    cvss = cyber_ops.math_cvss_score(0.64, 0.64, 0.64, "network", "low", "none")
    print(f"  CVSS Score: {cvss.base_score} ({cvss.severity})")

if __name__ == "__main__":
    demonstrate_cyberteam_operations()