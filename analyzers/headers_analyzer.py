"""
Binary headers inspection analyzer using LIEF
Analyzes PE, ELF, and Mach-O executables
"""
import lief
from typing import Dict, Any, List, Optional
from .base import BaseAnalyzer, AnalysisResult

class HeadersAnalyzer(BaseAnalyzer):
    """Analyze binary headers and structure using LIEF"""
    
    def analyze(self, file_path: str, **kwargs) -> AnalysisResult:
        """Analyze binary headers and structure"""
        try:
            binary = lief.parse(file_path)
            if not binary:
                return AnalysisResult(
                    analyzer_name="Headers Inspector",
                    success=False,
                    error="Not a recognized binary format"
                )
            
            # Get format-specific analysis
            if binary.format == lief.EXE_FORMATS.PE:
                return self.analyze_pe(binary, file_path)
            elif binary.format == lief.EXE_FORMATS.ELF:
                return self.analyze_elf(binary, file_path)
            elif binary.format == lief.EXE_FORMATS.MACHO:
                return self.analyze_macho(binary, file_path)
            else:
                return self.analyze_generic(binary, file_path)
                
        except Exception as e:
            return AnalysisResult(
                analyzer_name="Headers Inspector",
                success=False,
                error=f"Failed to parse binary: {str(e)}"
            )
    
    def analyze_generic(self, binary: lief.Binary, file_path: str) -> AnalysisResult:
        """Generic binary analysis"""
        data = {
            "format": binary.format.name if binary.format else "Unknown",
            "entrypoint": hex(binary.entrypoint) if binary.entrypoint else "N/A",
            "sections": [s.name for s in binary.sections] if hasattr(binary, 'sections') else []
        }
        
        blocks = [{
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"📦 *Binary Headers*"},
            "fields": [
                {"type": "mrkdwn", "text": f"*Format:*\n{data['format']}"},
                {"type": "mrkdwn", "text": f"*Entry Point:*\n{data['entrypoint']}"},
                {"type": "mrkdwn", "text": f"*Sections:*\n{len(data['sections'])}"}
            ]
        }]
        
        return AnalysisResult(
            analyzer_name="Headers Inspector",
            success=True,
            data=data,
            slack_blocks=blocks
        )
    
    def analyze_pe(self, pe: lief.PE.Binary, file_path: str) -> AnalysisResult:
        """Analyze PE binary"""
        data = {
            "format": "PE",
            "machine": pe.header.machine.name if pe.header else "Unknown",
            "entrypoint": hex(pe.entrypoint),
            "timestamp": pe.header.time_date_stamp if pe.header else 0,
            "subsystem": pe.optional_header.subsystem.name if pe.optional_header else "Unknown",
            "dll_characteristics": []
        }
        
        # Sections
        sections_info = []
        suspicious_sections = []
        for section in pe.sections:
            sections_info.append({
                "name": section.name,
                "size": section.size,
                "virtual_size": section.virtual_size,
                "entropy": section.entropy
            })
            # Check for suspicious sections
            if section.name.lower() in [".upx", ".pdata", ".rsrc", ".textbss", ".code", ".adata"]:
                suspicious_sections.append(section.name)
        
        data["sections"] = sections_info
        data["suspicious_sections"] = suspicious_sections
        
        # Imports
        imports = []
        suspicious_imports = []
        for imp in pe.imports[:20]:  # Limit to first 20
            imports.append(imp.name)
            # Check for suspicious imports
            if any(sus in imp.name.lower() for sus in ["ntdll", "kernel32", "ws2_32", "wininet", "urlmon"]):
                suspicious_imports.append(imp.name)
        
        data["imports"] = imports
        data["suspicious_imports"] = suspicious_imports
        
        # Exports
        exports = []
        if pe.has_exports:
            for exp in pe.exported_functions[:10]:
                exports.append(exp.name if exp.name else f"Ordinal_{exp.ordinal}")
        data["exports"] = exports
        
        # DLL characteristics (security features)
        if pe.optional_header:
            chars = pe.optional_header.dll_characteristics_lists
            data["dll_characteristics"] = [c.name for c in chars] if chars else []
        
        # Build Slack blocks
        blocks = []
        
        # Header info
        security_emoji = "🛡️" if "DYNAMIC_BASE" in data["dll_characteristics"] else "⚠️"
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"📦 *PE Binary Analysis* {security_emoji}"},
            "fields": [
                {"type": "mrkdwn", "text": f"*Machine:*\n{data['machine']}"},
                {"type": "mrkdwn", "text": f"*Subsystem:*\n{data['subsystem']}"},
                {"type": "mrkdwn", "text": f"*Entry Point:*\n{data['entrypoint']}"},
                {"type": "mrkdwn", "text": f"*Sections:*\n{len(sections_info)}"}
            ]
        })
        
        # Security features
        if data["dll_characteristics"]:
            sec_features = ", ".join(data["dll_characteristics"][:5])
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"*Security:* {sec_features}"}]
            })
        
        # Suspicious indicators
        if suspicious_sections or suspicious_imports:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "⚠️ *Suspicious Indicators*"}
            })
            
            if suspicious_sections:
                blocks.append({
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": f"*Sections:* {', '.join(suspicious_sections)}"}]
                })
            
            if suspicious_imports:
                blocks.append({
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": f"*Imports:* {', '.join(suspicious_imports[:5])}"}]
                })
        
        # Imports/Exports summary
        if imports or exports:
            blocks.append({"type": "divider"})
            fields = []
            if imports:
                fields.append({"type": "mrkdwn", "text": f"*Imports:*\n{len(imports)} libraries"})
            if exports:
                fields.append({"type": "mrkdwn", "text": f"*Exports:*\n{len(exports)} functions"})
            
            if fields:
                blocks.append({
                    "type": "section",
                    "fields": fields
                })
        
        return AnalysisResult(
            analyzer_name="PE Headers Inspector",
            success=True,
            data=data,
            slack_blocks=blocks
        )
    
    def analyze_elf(self, elf: lief.ELF.Binary, file_path: str) -> AnalysisResult:
        """Analyze ELF binary"""
        data = {
            "format": "ELF",
            "file_type": elf.header.file_type.name if elf.header else "Unknown",
            "machine": elf.header.machine_type.name if elf.header else "Unknown",
            "entrypoint": hex(elf.entrypoint),
            "interpreter": elf.interpreter if hasattr(elf, 'interpreter') else None
        }
        
        # Sections
        sections_info = []
        for section in elf.sections:
            sections_info.append({
                "name": section.name,
                "size": section.size,
                "type": section.type.name if hasattr(section.type, 'name') else str(section.type)
            })
        data["sections"] = sections_info
        
        # Dynamic libraries
        libraries = []
        for lib in elf.libraries:
            libraries.append(lib)
        data["libraries"] = libraries
        
        # Imported/Exported functions
        imports = [f.name for f in elf.imported_functions[:20]]
        exports = [f.name for f in elf.exported_functions[:20]]
        data["imports"] = imports
        data["exports"] = exports
        
        # Security features
        security = {
            "nx": elf.has_nx if hasattr(elf, 'has_nx') else False,
            "pie": elf.is_pie if hasattr(elf, 'is_pie') else False,
            "relro": "Unknown"
        }
        
        # Check RELRO
        if hasattr(elf, 'segments'):
            for seg in elf.segments:
                if seg.type == lief.ELF.SEGMENT_TYPES.GNU_RELRO:
                    security["relro"] = "Full" if elf.has_section(".got.plt") else "Partial"
                    break
        
        data["security"] = security
        
        # Build Slack blocks
        blocks = []
        
        # Header info
        sec_score = sum([security["nx"], security["pie"], security["relro"] != "Unknown"])
        security_emoji = "🛡️" if sec_score >= 2 else "⚠️"
        
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"🐧 *ELF Binary Analysis* {security_emoji}"},
            "fields": [
                {"type": "mrkdwn", "text": f"*Type:*\n{data['file_type']}"},
                {"type": "mrkdwn", "text": f"*Machine:*\n{data['machine']}"},
                {"type": "mrkdwn", "text": f"*Entry Point:*\n{data['entrypoint']}"},
                {"type": "mrkdwn", "text": f"*Sections:*\n{len(sections_info)}"}
            ]
        })
        
        # Security features
        sec_text = f"NX: {'✅' if security['nx'] else '❌'}, PIE: {'✅' if security['pie'] else '❌'}, RELRO: {security['relro']}"
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"*Security:* {sec_text}"}]
        })
        
        # Libraries
        if libraries:
            blocks.append({"type": "divider"})
            lib_text = ", ".join(libraries[:5])
            if len(libraries) > 5:
                lib_text += f" (+{len(libraries)-5} more)"
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"*Libraries:* {lib_text}"}]
            })
        
        return AnalysisResult(
            analyzer_name="ELF Headers Inspector",
            success=True,
            data=data,
            slack_blocks=blocks
        )
    
    def analyze_macho(self, macho, file_path: str) -> AnalysisResult:
        """Analyze Mach-O binary"""
        # Handle FatBinary
        if isinstance(macho, lief.MachO.FatBinary):
            if len(macho) > 0:
                macho = macho.at(0)  # Take first architecture
            else:
                return AnalysisResult(
                    analyzer_name="Mach-O Headers Inspector",
                    success=False,
                    error="Empty FatBinary"
                )
        
        data = {
            "format": "Mach-O",
            "cpu_type": macho.header.cpu_type.name if macho.header else "Unknown",
            "file_type": macho.header.file_type.name if macho.header else "Unknown",
            "entrypoint": hex(macho.entrypoint),
            "commands": len(macho.commands)
        }
        
        # Sections
        sections_info = []
        for section in macho.sections:
            sections_info.append({
                "name": section.name,
                "size": section.size
            })
        data["sections"] = sections_info
        
        # Libraries
        libraries = []
        for lib in macho.libraries:
            libraries.append(lib.name)
        data["libraries"] = libraries
        
        # Code signing
        has_signature = macho.has_code_signature if hasattr(macho, 'has_code_signature') else False
        data["code_signed"] = has_signature
        
        # Build Slack blocks
        blocks = []
        
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"🍎 *Mach-O Binary Analysis* {'✅' if has_signature else '❌'}"},
            "fields": [
                {"type": "mrkdwn", "text": f"*CPU Type:*\n{data['cpu_type']}"},
                {"type": "mrkdwn", "text": f"*File Type:*\n{data['file_type']}"},
                {"type": "mrkdwn", "text": f"*Commands:*\n{data['commands']}"},
                {"type": "mrkdwn", "text": f"*Code Signed:*\n{'Yes' if has_signature else 'No'}"}
            ]
        })
        
        # Libraries
        if libraries:
            lib_text = ", ".join(libraries[:3])
            if len(libraries) > 3:
                lib_text += f" (+{len(libraries)-3} more)"
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"*Libraries:* {lib_text}"}]
            })
        
        return AnalysisResult(
            analyzer_name="Mach-O Headers Inspector",
            success=True,
            data=data,
            slack_blocks=blocks
        )