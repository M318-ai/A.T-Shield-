import os
import re
import uuid
from datetime import datetime
from typing import List, Dict, Optional
from enum import Enum

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import uvicorn
from pydantic import BaseModel

# ==================== MODELS ====================
class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Finding(BaseModel):
    type: str
    confidence: float
    snippet: str
    risk_level: RiskLevel

class ScanResult(BaseModel):
    scan_id: str
    status: str
    risk_score: int
    findings: List[Finding]
    summary: Dict[str, int]
    filename: str
    created_at: datetime

# ==================== AI SCANNER ====================
class AIScanner:
    PATTERNS = {
        "EMAIL": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "PHONE": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        "CREDIT_CARD": r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
        "API_KEY": r'\b(?:sk|pk)_[a-zA-Z0-9]{20,}\b',
    }
    
    @classmethod
    def scan_text(cls, text: str) -> List[Finding]:
        findings = []
        
        for pattern_name, pattern in cls.PATTERNS.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                risk = RiskLevel.CRITICAL if pattern_name in ["API_KEY", "CREDIT_CARD"] else RiskLevel.HIGH
                findings.append(Finding(
                    type=pattern_name,
                    confidence=0.95,
                    snippet=match.group(),
                    risk_level=risk
                ))
        
        return findings
    
    @classmethod
    def calculate_risk_score(cls, findings: List[Finding]) -> int:
        if not findings:
            return 0
        return min(len(findings) * 15, 100)

# ==================== DATABASE (In-memory) ====================
scans_db = {}

# ==================== FASTAPI APP ====================
app = FastAPI(title="את.שילד", version="2.0", docs_url="/docs", redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== DASHBOARD HTML ====================
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>את.שילד - Data Security Platform</title>
    <script src="[cdn.tailwindcss.com](https://cdn.tailwindcss.com)"></script>
    <link rel="stylesheet" href="[cdnjs.cloudflare.com](https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css)">
    <meta charset="UTF-8">
</head>
<body class="bg-gray-50 min-h-screen">
    <div class="container mx-auto px-4 py-8">
        <!-- Header -->
        <header class="mb-12">
            <h1 class="text-4xl font-bold text-center text-gray-900 mb-4">
                <i class="fas fa-shield-alt text-blue-600"></i>
                את.שילד
            </h1>
            <p class="text-center text-gray-600 text-lg">
                Data Security Platform - הגנה על מידע רגיש
            </p>
        </header>

        <!-- Stats -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
            <div class="bg-white p-6 rounded-xl shadow text-center">
                <div class="text-3xl font-bold text-blue-600" id="totalScans">0</div>
                <div class="text-gray-600 mt-2">סריקות בוצעו</div>
            </div>
            <div class="bg-white p-6 rounded-xl shadow text-center">
                <div class="text-3xl font-bold text-green-600" id="avgRisk">0%</div>
                <div class="text-gray-600 mt-2">סיכון ממוצע</div>
            </div>
            <div class="bg-white p-6 rounded-xl shadow text-center">
                <div class="text-3xl font-bold text-red-600" id="criticalFindings">0</div>
                <div class="text-gray-600 mt-2">ממצאים קריטיים</div>
            </div>
        </div>

        <!-- File Upload -->
        <div class="bg-white rounded-xl shadow-lg p-8 mb-8 max-w-2xl mx-auto">
            <h2 class="text-2xl font-bold mb-6">סרוק קובץ למידע רגיש</h2>
            
            <div class="border-2 border-dashed border-gray-300 rounded-lg p-12 text-center mb-6">
                <i class="fas fa-cloud-upload-alt text-5xl text-gray-400 mb-4"></i>
                <p class="text-gray-700 mb-2">גרור קובץ לכאן או לחץ לבחירה</p>
                <p class="text-gray-500 text-sm">מקבל: .txt, .csv, .json, .log</p>
                
                <input type="file" id="fileInput" class="hidden" accept=".txt,.csv,.json,.log,.xml">
                <button onclick="document.getElementById('fileInput').click()" 
                        class="mt-6 bg-blue-600 text-white px-8 py-3 rounded-lg font-semibold hover:bg-blue-700">
                    <i class="fas fa-search mr-2"></i> בחר קובץ לסריקה
                </button>
            </div>
            
            <button onclick="startScan()" 
                    id="scanBtn"
                    class="w-full bg-gradient-to-r from-blue-600 to-indigo-700 text-white py-4 rounded-lg font-semibold text-lg hover:opacity-90">
                התחל סריקת אבטחה
            </button>
            
            <div id="progress" class="hidden mt-6">
                <div class="flex justify-between mb-2">
                    <span>מתקדם...</span>
                    <span id="progressPercent">0%</span>
                </div>
                <div class="h-2 bg-gray-200 rounded-full">
                    <div id="progressBar" class="h-2 bg-green-500 rounded-full transition-all" style="width: 0%"></div>
                </div>
            </div>
        </div>

        <!-- Results -->
        <div id="results" class="hidden">
            <h2 class="text-2xl font-bold mb-6">תוצאות הסריקה</h2>
            
            <div class="bg-white rounded-xl shadow-lg p-6 mb-6">
                <div class="flex justify-between items-center">
                    <div>
                        <h3 class="text-xl font-bold" id="riskScoreTitle">ציון סיכון: <span id="riskScore" class="text-red-600">0%</span></h3>
                        <p class="text-gray-600" id="riskLevel">רמת סיכון: נמוכה</p>
                    </div>
                    <div class="text-right">
                        <p class="text-gray-600">ממצאים: <span id="findingsCount" class="font-bold">0</span></p>
                        <p class="text-gray-600">זמן סריקה: <span id="scanTime" class="font-bold">0s</span></p>
                    </div>
                </div>
            </div>

            <!-- Findings Table -->
            <div class="bg-white rounded-xl shadow-lg overflow-hidden">
                <table class="min-w-full">
                    <thead class="bg-gray-100">
                        <tr>
                            <th class="px-6 py-3 text-left font-semibold">סוג</th>
                            <th class="px-6 py-3 text-left font-semibold">סיכון</th>
                            <th class="px-6 py-3 text-left font-semibold">ביטחון</th>
                            <th class="px-6 py-3 text-left font-semibold">דוגמה</th>
                        </tr>
                    </thead>
                    <tbody id="findingsTable" class="divide-y divide-gray-200">
                        <!-- Dynamic content -->
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Recent Scans -->
        <div class="mt-12">
            <h2 class="text-2xl font-bold mb-6">סריקות אחרונות</h2>
            <div class="overflow-x-auto">
                <table class="min-w-full bg-white shadow rounded-lg">
                    <thead class="bg-gray-100">
                        <tr>
                            <th class="px-6 py-3 text-left">קובץ</th>
                            <th class="px-6 py-3 text-left">סטטוס</th>
                            <th class="px-6 py-3 text-left">סיכון</th>
                            <th class="px-6 py-3 text-left">זמן</th>
                        </tr>
                    </thead>
                    <tbody id="recentScansTable" class="divide-y divide-gray-200">
                        <!-- Dynamic -->
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Footer -->
        <footer class="mt-12 pt-8 border-t text-center text-gray-600">
            <p>את.שילד &copy; 2024 - Data Security Platform</p>
            <p class="text-sm mt-2">
                <a href="/pricing" class="text-blue-600 hover:underline">תמחור</a> | 
                <a href="/docs" class="text-blue-600 hover:underline">API</a>
            </p>
        </footer>
    </div>

    <script>
        let selectedFile = null;
        const scans = [];

        // File selection
        document.getElementById('fileInput').addEventListener('change', function(e) {
            selectedFile = e.target.files[0];
            if (selectedFile) {
                document.querySelector('.border-dashed').innerHTML = `
                    <i class="fas fa-check-circle text-green-500 text-5xl mb-4"></i>
                    <p class="text-gray-800 font-medium">קובץ נבחר</p>
                    <p class="text-gray-600 text-sm">${selectedFile.name}</p>
                    <button onclick="clearFile()" class="mt-4 text-red-600 hover:text-red-800 text-sm">
                        <i class="fas fa-times mr-1"></i> הסר בחירה
                    </button>
                `;
            }
        });

        function clearFile() {
            selectedFile = null;
            document.getElementById('fileInput').value = '';
            document.querySelector('.border-dashed').innerHTML = `
                <i class="fas fa-cloud-upload-alt text-5xl text-gray-400 mb-4"></i>
                <p class="text-gray-700 mb-2">גרור קובץ לכאן או לחץ לבחירה</p>
                <p class="text-gray-500 text-sm">מקבל: .txt, .csv, .json, .log</p>
                <button onclick="document.getElementById('fileInput').click()" 
                        class="mt-6 bg-blue-600 text-white px-8 py-3 rounded-lg font-semibold hover:bg-blue-700">
                    <i class="fas fa-search mr-2"></i> בחר קובץ לסריקה
                </button>
            `;
        }

        async function startScan() {
            if (!selectedFile) {
                alert('בחר קובץ תחילה');
                return;
            }

            const btn = document.getElementById('scanBtn');
            const progress = document.getElementById('progress');
            const progressBar = document.getElementById('progressBar');
            const progressPercent = document.getElementById('progressPercent');

            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i> סורק...';
            progress.classList.remove('hidden');
            progressBar.style.width = '30%';
            progressPercent.textContent = '30%';

            const formData = new FormData();
            formData.append('file', selectedFile);

            try {
                const startTime = Date.now();
                
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    body: formData
                });
                
                progressBar.style.width = '80%';
                progressPercent.textContent = '80%';

                if (response.ok) {
                    const result = await response.json();
                    scans.unshift(result);
                    
                    progressBar.style.width = '100%';
                    progressPercent.textContent = '100%';
                    
                    // Show results
                    displayResults(result);
                    
                    // Update stats
                    updateStats();
                    
                    // Update recent scans
                    updateRecentScans();
                    
                    // Reset
                    setTimeout(() => {
                        progress.classList.add('hidden');
                        btn.disabled = false;
                        btn.innerHTML = '<i class="fas fa-search mr-2"></i> התחל סריקת אבטחה';
                        progressBar.style.width = '0%';
                    }, 1000);
                    
                } else {
                    throw new Error('Scan failed');
                }
                
            } catch (error) {
                alert('שגיאה בסריקה: ' + error.message);
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-search mr-2"></i> התחל סריקת אבטחה';
                progress.classList.add('hidden');
            }
        }

        function displayResults(result) {
            document.getElementById('results').classList.remove('hidden');
            document.getElementById('riskScore').textContent = result.risk_score + '%';
            document.getElementById('findingsCount').textContent = result.findings.length;
            
            // Risk level
            let riskLevel = 'נמוכה';
            if (result.risk_score >= 70) riskLevel = 'גבוהה מאוד';
            else if (result.risk_score >= 50) riskLevel = 'גבוהה';
            else if (result.risk_score >= 30) riskLevel = 'בינונית';
            document.getElementById('riskLevel').textContent = 'רמת סיכון: ' + riskLevel;
            
            // Findings table
            const table = document.getElementById('findingsTable');
            table.innerHTML = '';
            
            result.findings.forEach(finding => {
                const row = document.createElement('tr');
                
                let riskColor = 'bg-green-100 text-green-800';
                if (finding.risk_level === 'high') riskColor = 'bg-orange-100 text-orange-800';
                if (finding.risk_level === 'critical') riskColor = 'bg-red-100 text-red-800';
                
                row.innerHTML = `
                    <td class="px-6 py-4">${finding.type}</td>
                    <td class="px-6 py-4">
                        <span class="px-3 py-1 rounded-full text-xs font-semibold ${riskColor}">
                            ${finding.risk_level}
                        </span>
                    </td>
                    <td class="px-6 py-4">${Math.round(finding.confidence * 100)}%</td>
                    <td class="px-6 py-4 font-mono text-sm">${finding.snippet}</td>
                `;
                table.appendChild(row);
            });
        }

        function updateStats() {
            document.getElementById('totalScans').textContent = scans.length;
            
            if (scans.length > 0) {
                const avgRisk = scans.reduce((sum, s) => sum + s.risk_score, 0) / scans.length;
                document.getElementById('avgRisk').textContent = Math.round(avgRisk) + '%';
                
                const critical = scans.filter(s => s.risk_score >= 70).length;
                document.getElementById('criticalFindings').textContent = critical;
            }
        }

        function updateRecentScans() {
            const table = document.getElementById('recentScansTable');
            table.innerHTML = '';
            
            scans.slice(0, 5).forEach(scan => {
                const row = document.createElement('tr');
                
                let statusColor = 'bg-green-100 text-green-800';
                let riskColor = 'text-green-600';
                if (scan.risk_score >= 70) riskColor = 'text-red-600';
                else if (scan.risk_score >= 50) riskColor = 'text-orange-600';
                
                row.innerHTML = `
                    <td class="px-6 py-4">${scan.filename || 'קובץ'}</td>
                    <td class="px-6 py-4">
                        <span class="px-2 py-1 rounded text-xs ${statusColor}">
                            ${scan.status}
                        </span>
                    </td>
                    <td class="px-6 py-4 font-bold ${riskColor}">
                        ${scan.risk_score}%
                    </td>
                    <td class="px-6 py-4 text-gray-500 text-sm">
                        ${new Date(scan.created_at).toLocaleTimeString()}
                    </td>
                `;
                table.appendChild(row);
            });
        }

        // Initial load
        async function loadRecentScans() {
            try {
                const response = await fetch('/api/scans');
                const data = await response.json();
                if (data.scans) {
                    scans.push(...data.scans);
                    updateStats();
                    updateRecentScans();
                }
            } catch (error) {
                console.log('No previous scans');
            }
        }
        loadRecentScans();
    </script>
</body>
</html>
"""

# ==================== ROUTES ====================
@app.get("/", response_class=HTMLResponse)
async def home():
    return HTMLResponse(content=DASHBOARD_HTML)

@app.post("/api/scan")
async def scan_file(file: UploadFile = File(...)):
    try:
        content = await file.read()
        text = content.decode('utf-8', errors='ignore')
        
        findings = AIScanner.scan_text(text)
        risk_score = AIScanner.calculate_risk_score(findings)
        
        scan_id = str(uuid.uuid4())
        scan_result = ScanResult(
            scan_id=scan_id,
            status="completed",
            risk_score=risk_score,
            findings=findings,
            summary={f.type: sum(1 for x in findings if x.type == f.type) for f in findings},
            filename=file.filename,
            created_at=datetime.now()
        )
        
        scans_db[scan_id] = scan_result.dict()
        
        return scan_result.dict()
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@app.get("/api/scans")
async def get_scans():
    return {"scans": list(scans_db.values())}

@app.get("/pricing", response_class=HTMLResponse)
async def pricing():
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head><title>תמחור - את.שילד</title>
    <script src="[cdn.tailwindcss.com](https://cdn.tailwindcss.com)"></script></head>
    <body class="bg-gray-50 p-8">
        <div class="max-w-4xl mx-auto">
            <h1 class="text-3xl font-bold mb-8">תוכניות מחיר</h1>
            <div class="grid md:grid-cols-3 gap-6">
                <div class="bg-white p-6 rounded-xl shadow">
                    <h3 class="text-xl font-bold mb-4">חינם</h3>
                    <p class="text-3xl font-bold mb-4">$0<span class="text-gray-500 text-lg">/חודש</span></p>
                    <ul class="space-y-2 mb-6">
                        <li>✓ 10 סריקות בחודש</li>
                        <li>✓ זיהוי PII בסיסי</li>
                        <li>✓ דשבורד פשוט</li>
                    </ul>
                    <button class="w-full bg-gray-200 py-3 rounded-lg">התחל חינם</button>
                </div>
                
                <div class="bg-white p-6 rounded-xl shadow border-2 border-blue-500 relative">
                    <div class="absolute -top-3 left-1/2 transform -translate-x-1/2 bg-blue-500 text-white px-4 py-1 rounded-full">פופולרי</div>
                    <h3 class="text-xl font-bold mb-4">Professional</h3>
                    <p class="text-3xl font-bold mb-4">$29<span class="text-gray-500 text-lg">/חודש</span></p>
                    <ul class="space-y-2 mb-6">
                        <li>✓ 500 סריקות בחודש</li>
                        <li>✓ AWS S3 integration</li>
                        <li>✓ Google Drive scanning</li>
                        <li>✓ PDF reports</li>
                    </ul>
                    <button class="w-full bg-blue-600 text-white py-3 rounded-lg hover:bg-blue-700">התחל חינם 14 יום</button>
                </div>
                
                <div class="bg-white p-6 rounded-xl shadow">
                    <h3 class="text-xl font-bold mb-4">Enterprise</h3>
                    <p class="text-3xl font-bold mb-4">$99<span class="text-gray-500 text-lg">/חודש</span></p>
                    <ul class="space-y-2 mb-6">
                        <li>✓ סריקות ללא הגבלה</li>
                        <li>✓ Microsoft 365 integration</li>
                        <li>✓ Custom AI models</li>
                        <li>✓ SSO & API access</li>
                    </ul>
                    <button class="w-full bg-gray-800 text-white py-3 rounded-lg hover:bg-black">צור קשר</button>
                </div>
            </div>
        </div>
    </body>
    </html>
    """)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"🚀 את.שילד מתחיל על פורט {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
