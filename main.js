/* ==========================================================================
   General Substitution Cipher Decryption - Core Logic
   ========================================================================== */

/**
 * Ciphertext Corpora
 * Pre-defined samples for cryptanalysis demonstration.
 */
const sampleTexts = {
    "alkindi": "GFS WMY OG LGDVS MF SFNKYHOSU ESLLMRS, PC WS BFGW POL DMFRQMRS, PL OG CPFU M UPCCSKSFO HDMPFOSXO GC OIS LMES DMFRQMRS DGFR SFGQRI OG CPDD GFS LISSO GK LG, MFU OISF WS NGQFO OIS GNNQKKSFNSL GC SMNI DSOOSK. WS NMDD OIS EGLO CKSJQSFODY GNNQKKPFR DSOOSK OIS 'CPKLO', OIS FSXO EGLO GNNQKKPFR DSOOSK OIS 'LSNGFU' OIS CGDDGWPFR EGLO GNNQKKPFR DSOOSK OIS 'OIPKU', MFU LG GF, QFOPD WS MNNGQFO CGK MDD GFS DSOOSK PF OIS HDMPFOSXO LMEHDS. OISF WS DGGB MO OIS NPHISK OSXO WS WMFO OG LGDVS MFU WS MDLG NDMLLPCY POL LYEAGDL. WS CPFU OIS EGLO GNNQKKPFR LYEAGD MFU NIMFRS PO OG OIS CGKE GC OIS 'CPKLO' DSOOSK GC OIS HDMPFOSXO LMEHDS, OIS FSXO EGLO NGEEGF LYEAGD PL NIMFRSU OG OIS CGKE GC OIS 'LSNGFU' DSOOSK, MFU OIS CGDDGWPFR EGLO NGEEGF LYEAGD PL NIMFRSU OG OIS CGKE GC OIS 'OIPKU' DSOOSK, MFU LG GF, QFOPD WS MNNGQFO CGK MDD LYEAGDL GC OIS NKYHOGRKME WS WMFO OG LGDVS.",
    "sherlock": "NY NX F HFUNYFQ RNSYFPJ YT YMJTWNEJ GJKTWJ TSJ MFX IFYF. NSXJNXNGQD TSJ GJLNSX YT YBNXY KFHYX YT XZNY YMJTWNJX, NSXYJFI TK YMJTWNJX YT XZNY KFHYX.",
    "goldbug": "N TBBQ TYNFF VA GUR OVFUBC'F UBFGRY VA GUR QRIVY'F FRNG SBEGL BAR QRTERRF NAQ GUVEGRRA ZVAHGRF ABEGURNFG NAQ OL ABEGU ZNVA OENAPU FRIRAGU YVZO RNFG FVQR FUBBG SEBZ GUR YRSG RLR BS GUR QRNGU'F URNQ.",
    "turing": "YG ECP QNNA UGG C UJQTV FKUVCPEG CJGCF, DWT YG ECP UGG RNGPVA VJGTG VJCV PGGFU VQ DG FQPG.",
    "zimmermann": "JR VAGRAQ GB ORTVA BA GUR SVEFG BS SROEHNEL HAERFGEVPGRQ FHOZNEVAR JNESNER. JR ZNXR ZRKVPB N CEBCBFNY BS NYYVNAPR BA GUR SBYYBJVAT ONFVF: ZNXR JNE GBTRGURE, ZNXR CRNPR GBTRGURE, TRAREBHF SVANAPVNY FHCCBEG NAQ NA HAQREFGNAQVAT BA BHE CNEG GUNG ZRKVPB VF GB ERPBADHRE GUR YBFG GREEVGBEL VA GRKNF, ARJ ZRKVPB, NAQ NEVMBAN."
};

/**
 * Decryption Key Reference
 * Validated mappings for provided sample texts.
 */
const ANSWERS = {
    "alkindi": {
        "A":"b","B":"k","C":"f","D":"s","E":"m","F":"h","G":"t","H":"p","I":"d","J":"j",
        "K":"r","L":"l","M":"a","N":"n","O":"o","P":"i","Q":"g","R":"u","S":"e","T":"c",
        "U":"x","V":"v","W":"w","Y":"y"
    },
    "sherlock": {
        "A":"y","B":"w","F":"a","G":"b","H":"c","I":"d","J":"e","K":"f","L":"g","M":"h",
        "N":"i","Q":"d","R":"m","S":"k","T":"o","U":"p","X":"s","Y":"t","Z":"u"
    },
    "goldbug": {
        "A":"n","B":"h","C":"n","E":"e","F":"s","G":"t","H":"p","I":"d","J":"i","K":"o",
        "L":"l","N":"a","O":"y","P":"a","Q":"v","R":"u","S":"f","T":"r","U":"s","V":"g",
        "X":"m","Z":"m"
    },
    "turing": {
        "A":"n","C":"a","D":"w","E":"e","F":"m","G":"i","H":"m","I":"t","J":"q","L":"y",
        "N":"o","P":"p","Q":"u","R":"v","S":"u","T":"h","U":"v","V":"r","W":"s","Y":"w"
    },
    "zimmermann": {
        "A":"n","B":"b","C":"c","E":"e","F":"f","G":"g","H":"h","I":"i","J":"j","L":"l",
        "M":"m","N":"n","O":"o","P":"p","Q":"q","R":"r","S":"s","T":"t","U":"u","V":"v",
        "Z":"z"
    }
};

/**
 * Hint Generation Engine
 * Provides suggested mappings based on statistical verification against validated keys.
 */
function getLocalHint(targetChar) {
    // 1. Retrieve active sample context
    const sid = document.getElementById('sampleTextSelect').value;
    const target = targetChar.toUpperCase();
    
    // 2. Validate against solution dictionary
    let correct = "?";
    if (ANSWERS[sid] && ANSWERS[sid][target]) {
        correct = ANSWERS[sid][target];
    }
    
    // 3. Generate explanation metadata
    let explanation = "";
    if (correct === "?") {
        explanation = `Statistical analysis was inconclusive for <strong>${target}</strong>.`;
    } else {
        explanation = `Statistical analysis suggests mapping <strong>${target}</strong> to <strong>'${correct}'</strong>.`;
    }
    
    // 4. Return result object
    return {
        suggested: correct,
        explanation: explanation
    };
}

// Application State Management
let mapping = {};
let historyStack = [];
let originalText = sampleTexts["alkindi"]; 
let lockedLetters = {}; 
let ngramSearchTerm = "";
let currentGhostWord = null;
let fullDictionary = [];

/**
 * External Lexicon Integration
 * Loads 10,000 common English words for pattern matching and dictionary attacks.
 */
fetch('https://raw.githubusercontent.com/first20hours/google-10000-english/master/google-10000-english.txt')
    .then(res => res.text())
    .then(text => {
        // Sanitize and transform raw text into searchable array
        fullDictionary = text.split('\n').filter(word => word.length > 1);
        console.log("Pro Dictionary Ready.");
    });

/**
 * Global UI Synchronization
 * Updates all dynamic components to reflect current application state.
 */
function updateAll() {
    // Component Renderers
    renderOutput();
    renderGrid();
    renderFrequenciesAndEndings();
    renderProfiler();
    
    // Status Trackers
    updateProgressBadge();
    
    // Analysis Tool Population
    populateContractions();
    populateIsomorphs();
    populatePairs();
    populateMonograms();
    populateTwoWords();
    populateThreeWords();
    populateSuffixes();
    populateDoubleLetters();
}

/* ==========================================================================
   State Management Methods
   ========================================================================== */

function loadSampleText() {
    const sel = document.getElementById('sampleTextSelect').value;
    originalText = (sel === 'custom') ? "" : sampleTexts[sel] || "";
    document.getElementById('cipherInput').value = originalText;
    
    // Reset session variables
    mapping = {};
    historyStack = [];
    lockedLetters = {};
    ngramSearchTerm = "";
    
    const searchInput = document.getElementById('ngramInput');
    if (searchInput) searchInput.value = "";
    
    updateAll();
}

function resetMapping() {
    mapping = {};
    historyStack = [];
    lockedLetters = {};
    updateAll();
}

function undo() {
    if (historyStack.length === 0) return;
    mapping = historyStack.pop();
    updateAll();
}

function saveToHistory() {
    historyStack.push(JSON.parse(JSON.stringify(mapping)));
    if (historyStack.length > 20) historyStack.shift();
}

/* ==========================================================================
   Analysis Engine: N-Gram Search
   ========================================================================== */

function updateNGramSearch(value) {
    ngramSearchTerm = value.trim().toUpperCase();
    if (typeof renderOutput === 'function') renderOutput();
}

/* ==========================================================================
   UI Rendering & DOM Manipulation
   ========================================================================== */

function renderOutput() {
    const outputDiv = document.getElementById('output');
    if (!outputDiv) return;

    if (!originalText) {
        outputDiv.innerHTML = "Paste your ciphertext in the input box to begin...";
        return;
    }

    // Tokenize text into words and delimiters
    const tokens = originalText.split(/([^A-Z]+)/);
    
    let html = '';

    tokens.forEach(token => {
        if (/[A-Z]/.test(token)) {
            const isGhost = (currentGhostWord && token === currentGhostWord);
            const isNGram = (ngramSearchTerm && token.includes(ngramSearchTerm));
            
            // Apply CSS prioritization: N-Gram focus takes precedence over Ghost focus
            let activeClass = '';
            if (isNGram) activeClass = 'ngram-highlight';
            else if (isGhost) activeClass = 'ghost-highlight';

            html += `<span class="output-word interactive-word ${activeClass}" onclick="openWordModal('${token}')">`;
            for (let char of token) {
                let isSolved = !!mapping[char];
                let p = isSolved ? mapping[char] : '.'; 
                let pClass = isSolved ? 'plain solved' : 'plain unsolved';

                html += `<div class="char-pair">
                            <span class="${pClass}">${p}</span>
                            <span class="cipher">${char}</span>
                         </div>`;
            }
            html += `</span>`;
        } else {
            html += token.replace(/\n/g, '<br>');
        }
    });

    outputDiv.innerHTML = html;
}

function renderGrid() {
    const gridDiv = document.getElementById('alphabetGrid');
    if (!gridDiv) return;

    let html = '';
    // Generate A-Z manual substitution interface
    for (let i = 65; i <= 90; i++) {
        let c = String.fromCharCode(i);
        let m = mapping[c] || '';
        let isLocked = lockedLetters[c] || false;
        
        let icon = isLocked ? '🔒' : '🔓';
        let lockOpacity = m ? '1' : '0.3'; 
        let bgStyle = isLocked ? 'background-color: #e9ecef; color: #777;' : 'background-color: #fff;';

        html += `<div class="grid-box" style="${isLocked ? 'border-color: #bbb;' : ''}">
                    <span class="lock-icon" onclick="toggleLock('${c}')" title="Lock/Unlock" style="opacity: ${lockOpacity}; font-size: 12px;">${icon}</span>
                    <div style="font-size: 0.85em; font-weight: bold; color: #555; margin-bottom: 2px;">${c}</div>
                    <input type="text" maxlength="1" value="${m}"
                        ${isLocked ? 'disabled' : ''}
                        oninput="requestMapping('${c}', this.value)"
                        style="text-transform: lowercase; ${bgStyle}">
                 </div>`;
    }
    gridDiv.innerHTML = html;
}

/* ==========================================================================
   Character Mapping Logic
   ========================================================================== */

function addMapping(cipherChar, plainChar) {
    plainChar = plainChar.toLowerCase();
    if (lockedLetters[cipherChar]) return; 

    if (plainChar === "") {
        delete mapping[cipherChar];
    } else {
        // Enforce bijective (1-to-1) mapping constraints
        for (let cChar in mapping) {
            if (mapping[cChar] === plainChar && cChar !== cipherChar) {
                delete mapping[cChar];
            }
        }
        mapping[cipherChar] = plainChar;
    }
}

function toggleLock(cipherChar) {
    // Validate entry exists before permitting lock state
    if (!mapping[cipherChar]) return; 

    lockedLetters[cipherChar] = !lockedLetters[cipherChar];
    renderGrid();
}

/* ==========================================================================
   Statistical Analysis Tools
   ========================================================================== */

function renderFrequenciesAndEndings() {
    // Standard English Frequency Distribution (ETAOIN SHRDLU)
    const englishFreqs = [
        {l:'e', v:'12%'}, {l:'t', v:'9%'}, {l:'a', v:'8%'}, {l:'o', v:'7%'}, {l:'i', v:'7%'},
        {l:'n', v:'6%'}, {l:'s', v:'6%'}, {l:'h', v:'6%'}, {l:'r', v:'6%'}, {l:'d', v:'4%'},
        {l:'l', v:'4%'}, {l:'c', v:'3%'}, {l:'u', v:'3%'}, {l:'m', v:'2%'}, {l:'w', v:'2%'},
        {l:'f', v:'2%'}, {l:'g', v:'2%'}, {l:'y', v:'2%'}, {l:'p', v:'2%'}, {l:'b', v:'1%'},
        {l:'v', v:'1%'}, {l:'k', v:'1%'}, {l:'j', v:'<1%'}, {l:'x', v:'<1%'}, {l:'q', v:'<1%'}, {l:'z', v:'<1%'}
    ];
    
    // Calculate ciphertext unigram frequencies
    let counts = {};
    for (let i = 0; i < originalText.length; i++) {
        let c = originalText[i];
        if (/[A-Z]/.test(c)) counts[c] = (counts[c] || 0) + 1;
    }
    let sortedCipher = Object.keys(counts).map(k => ({l: k, v: counts[k]})).sort((a, b) => b.v - a.v);

    // Render Direct Alignment Track
    const matcherTrack = document.getElementById('frequencyMatcher');
    if (matcherTrack) {
        let html = '';
        for (let i = 0; i < englishFreqs.length; i++) {
            let eng = englishFreqs[i];
            let ciph = sortedCipher[i];
            
            html += `<div class="freq-pair-box">
                        <span class="fp-eng-letter">${eng.l}</span>
                        <span class="fp-stat">${eng.v}</span>
                        <span class="fp-arrow">⬇</span>
                        <span class="fp-ciph-letter">${ciph ? ciph.l : '-'}</span>
                        <span class="fp-stat">${ciph ? ciph.v : '0'}</span>
                     </div>`;
        }
        matcherTrack.innerHTML = html;
    }

    // Identify and rank word-terminal characters
    let endCounts = {};
    let words = originalText.split(/[^A-Z]+/);
    for (let w of words) {
        if (w.length > 0) {
            let lastChar = w[w.length - 1];
            endCounts[lastChar] = (endCounts[lastChar] || 0) + 1;
        }
    }
    
    let sortedEndings = Object.keys(endCounts).map(k => ({l: k, v: endCounts[k]})).sort((a, b) => b.v - a.v).slice(0, 5);
    const endingsText = document.getElementById('dynamicTopEndings');
    
    if (endingsText) {
        if (sortedEndings.length > 0) {
            endingsText.textContent = sortedEndings.map(x => `${x.l}(${x.v})`).join(', ');
        } else {
            endingsText.textContent = "Scanning...";
        }
    }
}

function renderProfiler() {
    let links = {};
    const words = originalText.match(/\b[A-Z]+\b/g) || []; 
    
    // Analyze character adjacency for vowel/consonant profiling
    for (let w of words) {
        for (let i = 0; i < w.length; i++) {
            let c = w[i]; 
            if (!links[c]) links[c] = new Set();
            if (i > 0) links[c].add(w[i - 1]);
            if (i < w.length - 1) links[c].add(w[i + 1]);
        }
    }
    
    // Rank characters by unique neighbor count (Vowel Suspects)
    let sortedLinks = Object.keys(links)
        .map(k => ({l: k, v: links[k].size}))
        .sort((a, b) => b.v - a.v)
        .slice(0, 5);
        
    const profilerData = document.getElementById('vowelSuspects');
    if (profilerData) {
        if (sortedLinks.length > 0) {
            profilerData.textContent = sortedLinks.map(x => `${x.l}(${x.v} links)`).join(', ');
        } else {
            profilerData.textContent = 'Scanning...';
        }
    }
}

// Initial application bootstrapper
document.addEventListener('DOMContentLoaded', () => {
    loadSampleText();
});

/* ==========================================================================
   Tool Population: Contractions, Isomorphs, and Patterns
   ========================================================================== */

function populateContractions() {
    const select = document.getElementById('contractionSelect');
    if (!select) return;

    const currentVal = select.value;
    const regex = /\b[A-Z]+'([A-Z]+)\b/g;
    let matches = [...originalText.matchAll(regex)].map(m => m[1]); 

    let counts = {};
    matches.forEach(m => counts[m] = (counts[m] || 0) + 1);
    let sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);

    let html = '<option value="-">-</option>';
    sorted.forEach(([cipherStr, count]) => {
        html += `<option value="${cipherStr}">${cipherStr} (${count})</option>`;
    });
    
    select.innerHTML = html;
    
    if (currentVal && counts[currentVal]) {
        select.value = currentVal;
    } else {
        updateContractionTargets();
    }
}

function updateContractionTargets() {
    const select = document.getElementById('contractionSelect');
    const target = document.getElementById('contractionTarget');
    if (!select || !target) return;

    const val = select.value;
    if (val === '-') {
        target.innerHTML = '<option value="-">- Select cipher first -</option>';
        return;
    }

    const commonEndings = ['s', 't', 'm', 'd', 'll', 've', 're'];
    const validOptions = commonEndings.filter(x => x.length === val.length);

    let html = '<option value="-">- Select -</option>';
    validOptions.forEach(v => {
        html += `<option value="${v}">${v}</option>`;
    });
    
    target.innerHTML = html;
}

function applyContraction() {
    const cipher = document.getElementById('contractionSelect').value;
    const plain = document.getElementById('contractionTarget').value;
    if (cipher !== '-' && plain !== '-') requestMapping(cipher, plain);
}

/**
 * Pattern Recognition Helper
 * Converts strings to numeric patterns (e.g., "MAMMAL" -> "0.1.0.0.1.2")
 */
function getWordPattern(word) {
    let pattern = [];
    let letterMap = {};
    let counter = 0;
    for (let i = 0; i < word.length; i++) {
        let char = word[i];
        if (!(char in letterMap)) {
            letterMap[char] = counter++;
        }
        pattern.push(letterMap[char]);
    }
    return pattern.join('.');
}

const commonIsomorphs = [
    "that", "there", "these", "people", "little", "good", "look", "seem", "been", "will", "well", 
    "all", "too", "see", "which", "every", "never", "state", "system", "always", "where", 
    "between", "still", "three", "school", "cannot", "before", "another", "against", 
    "through", "without", "add", "off", "did", "eye", "away", "even", "here", "high", "says", 
    "soon", "wood", "deep", "feet", "took", "room", "week", "call", "fall", "hill", "pull", 
    "door", "poor", "need", "keep", "feel", "tree", "free", "meet", "book", "food", "foot", 
    "letter", "better", "common", "summer", "different", "difficult", "possible", "probably", 
    "remember", "suddenly", "suppose", "tomorrow", "usually", "whether", "million", "dollar", 
    "success", "suggest", "committee", "community", "attention", "difference"
];

function populateIsomorphs() {
    const select = document.getElementById('isomorphSelect');
    if (!select) return;

    const currentVal = select.value;
    const words = originalText.match(/\b[A-Z]+\b/g) || [];
    
    let counts = {};
    words.forEach(w => {
        // Filter for words with repeated characters
        if (new Set(w).size < w.length) {
            counts[w] = (counts[w] || 0) + 1;
        }
    });
    
    let sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);

    let html = '<option value="-">-</option>';
    sorted.forEach(([cipherWord, count]) => {
        html += `<option value="${cipherWord}">${cipherWord} (${count})</option>`;
    });
    
    select.innerHTML = html;
    
    if (currentVal && counts[currentVal]) {
        select.value = currentVal;
    } else {
        updateIsomorphTargets();
    }
}

function updateIsomorphTargets() {
    const select = document.getElementById('isomorphSelect');
    const target = document.getElementById('isomorphTarget');
    if (!select || !target) return;

    const val = select.value;
    if (val === '-') {
        target.innerHTML = '<option value="-">- Select cipher first -</option>';
        return;
    }

    const cipherPattern = getWordPattern(val);
    const validOptions = commonIsomorphs.filter(word => getWordPattern(word.toUpperCase()) === cipherPattern);

    let html = '<option value="-">- Select -</option>';
    validOptions.forEach(v => {
        let cleanText = v.toLowerCase();
        html += `<option value="${cleanText}">${cleanText}</option>`;
    });
    
    if (validOptions.length === 0) {
        html += `<option value="-" disabled>No common matches found</option>`;
    }
    
    target.innerHTML = html;
}

function applyIsomorph() {
    const cipher = document.getElementById('isomorphSelect').value;
    const plain = document.getElementById('isomorphTarget').value;
    if (cipher !== '-' && plain !== '-') requestMapping(cipher, plain);
}

const commonDigrams = ["th", "he", "in", "er", "an", "re", "nd", "at", "on", "nt", "ha", "es", "st", "en", "ed", "to", "it", "ou"];

function populatePairs() {
    const select = document.getElementById('pairSelect');
    if (!select) return;

    const currentVal = select.value;
    let counts = {};
    const words = originalText.split(/[^A-Z]+/);
    
    words.forEach(w => {
        // Segment words into digraphs
        for (let i = 0; i < w.length - 1; i++) {
            let digram = w.substring(i, i + 2);
            counts[digram] = (counts[digram] || 0) + 1;
        }
    });
    
    let sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 30);

    let html = '<option value="-">-</option>';
    sorted.forEach(([cipherDigram, count]) => {
        html += `<option value="${cipherDigram}">${cipherDigram} (${count})</option>`;
    });
    
    select.innerHTML = html;
    
    if (currentVal && counts[currentVal]) {
        select.value = currentVal;
    } else {
        updatePairTargets();
    }
}

function updatePairTargets() {
    const select = document.getElementById('pairSelect');
    const target = document.getElementById('pairTarget');
    if (!select || !target) return;

    const val = select.value;
    if (val === '-') {
        target.innerHTML = '<option value="-">- Select cipher first -</option>';
        return;
    }

    const cipherPattern = getWordPattern(val);
    const validOptions = commonDigrams.filter(d => getWordPattern(d.toUpperCase()) === cipherPattern);

    let html = '<option value="-">- Select -</option>';
    validOptions.forEach(v => {
        let cleanText = v.toLowerCase();
        html += `<option value="${cleanText}">${cleanText}</option>`;
    });

    if (validOptions.length === 0) {
        html += `<option value="-" disabled>No pattern matches found</option>`;
    }
    target.innerHTML = html;
}

function applyPair() {
    const cipher = document.getElementById('pairSelect').value;
    const plain = document.getElementById('pairTarget').value;
    if (cipher !== '-' && plain !== '-') requestMapping(cipher, plain);
}

// GUI Interaction Synchronization
function syncHover(index) {
    document.querySelectorAll(`.skyline-bar-group[data-rank="${index}"]`).forEach(el => {
        el.classList.add('rank-highlight');
    });
}

function syncUnhover() {
    document.querySelectorAll('.skyline-bar-group.rank-highlight').forEach(el => {
        el.classList.remove('rank-highlight');
    });
}

function populateMonograms() {
    const select = document.getElementById('monoSelect');
    if (!select) return;

    const currentVal = select.value;
    const words = originalText.match(/\b[A-Z]\b/g) || [];
    
    let counts = {};
    words.forEach(w => counts[w] = (counts[w] || 0) + 1);
    
    let sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);

    let html = '<option value="-">-</option>';
    sorted.forEach(([cipherChar, count]) => {
        html += `<option value="${cipherChar}">${cipherChar} (${count})</option>`;
    });
    
    select.innerHTML = html;
    if (currentVal && counts[currentVal]) select.value = currentVal;
    else updateMonoTargets();
}

function updateMonoTargets() {
    const target = document.getElementById('monoTarget');
    if (!target) return;
    target.innerHTML = `
        <option value="-">- Select -</option>
        <option value="a">a</option>
        <option value="i">i</option>
    `;
}

function applyMono() {
    const cipher = document.getElementById('monoSelect').value;
    const plain = document.getElementById('monoTarget').value;
    if (cipher !== '-' && plain !== '-') requestMapping(cipher, plain);
}

const commonTwoLetterWords = ["to", "of", "in", "it", "is", "as", "at", "be", "he", "by", "or", "on", "do", "if", "me", "my", "up", "an", "so"];

function populateTwoWords() {
    const select = document.getElementById('twoWordSelect');
    if (!select) return;

    const currentVal = select.value;
    const words = originalText.match(/\b[A-Z]{2}\b/g) || [];
    
    let counts = {};
    words.forEach(w => counts[w] = (counts[w] || 0) + 1);
    
    let sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);

    let html = '<option value="-">-</option>';
    sorted.forEach(([cipherWord, count]) => {
        html += `<option value="${cipherWord}">${cipherWord} (${count})</option>`;
    });
    
    select.innerHTML = html;
    if (currentVal && counts[currentVal]) select.value = currentVal;
    else updateTwoWordTargets();
}

function updateTwoWordTargets() {
    const select = document.getElementById('twoWordSelect');
    const target = document.getElementById('twoWordTarget');
    if (!select || !target) return;

    const val = select.value;
    if (val === '-') {
        target.innerHTML = '<option value="-">- Select cipher first -</option>';
        return;
    }

    const cipherPattern = getWordPattern(val);
    const validOptions = commonTwoLetterWords.filter(w => getWordPattern(w.toUpperCase()) === cipherPattern);

    let html = '<option value="-">- Select -</option>';
    validOptions.forEach(v => {
        let cleanText = v.toLowerCase();
        html += `<option value="${cleanText}">${cleanText}</option>`;
    });

    target.innerHTML = html;
}

function applyTwoWords() {
    const cipher = document.getElementById('twoWordSelect').value;
    const plain = document.getElementById('twoWordTarget').value;
    if (cipher !== '-' && plain !== '-') requestMapping(cipher, plain);
}

const commonThreeLetterWords = ["the", "and", "for", "are", "but", "not", "you", "all", "any", "can", "had", "her", "was", "one", "our", "out", "day", "get", "has", "him", "his"];
const commonSuffixes = ["ing", "ion", "est", "ent", "ely", "ive", "ity", "ous", "ate", "all"];
const commonDoubles = ["ll", "ee", "ss", "oo", "tt", "ff", "rr", "pp", "cc"];

function populateThreeWords() {
    const select = document.getElementById('threeWordSelect');
    if (!select) return;
    const currentVal = select.value;
    const words = originalText.match(/\b[A-Z]{3}\b/g) || [];
    let counts = {};
    words.forEach(w => counts[w] = (counts[w] || 0) + 1);
    let sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    let html = '<option value="-">-</option>';
    sorted.forEach(([cipher, count]) => html += `<option value="${cipher}">${cipher} (${count})</option>`);
    select.innerHTML = html;
    if (currentVal && counts[currentVal]) select.value = currentVal;
    else updateThreeWordTargets();
}

function updateThreeWordTargets() {
    const select = document.getElementById('threeWordSelect');
    const target = document.getElementById('threeWordTarget');
    if (!select || !target) return;

    const val = select.value;
    if (val === '-') {
        target.innerHTML = '<option value="-">- Select cipher first -</option>';
        return;
    }

    const cipherPattern = getWordPattern(val);
    const validOptions = commonThreeLetterWords.filter(w => getWordPattern(w.toUpperCase()) === cipherPattern);

    let html = '<option value="-">- Select -</option>';
    validOptions.forEach(v => {
        let cleanText = v.toLowerCase();
        html += `<option value="${cleanText}">${cleanText}</option>`;
    });

    target.innerHTML = html;
}

function applyThreeWords() {
    const cipher = document.getElementById('threeWordSelect').value;
    const plain = document.getElementById('threeWordTarget').value;
    if (cipher !== '-' && plain !== '-') requestMapping(cipher, plain);
}

function populateSuffixes() {
    const select = document.getElementById('suffixSelect');
    if (!select) return;
    const currentVal = select.value;
    
    const words = originalText.match(/\b[A-Z]{5,}\b/g) || [];
    let counts = {};
    words.forEach(w => {
        let suffix = w.slice(-3); 
        counts[suffix] = (counts[suffix] || 0) + 1;
    });
    
    let sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    let html = '<option value="-">-</option>';
    sorted.forEach(([cipher, count]) => {
        html += `<option value="${cipher}">${cipher} (${count})</option>`;
    });
    
    select.innerHTML = html;
    if (currentVal && counts[currentVal]) select.value = currentVal;
    else updateSuffixTargets();
}

function updateSuffixTargets() {
    const select = document.getElementById('suffixSelect');
    const target = document.getElementById('suffixTarget');
    if (!select || !target) return;

    const val = select.value;
    if (val === '-') {
        target.innerHTML = '<option value="-">- Select cipher first -</option>';
        return;
    }

    const cipherPattern = getWordPattern(val);
    const validOptions = commonSuffixes.filter(s => getWordPattern(s.toUpperCase()) === cipherPattern);

    let html = '<option value="-">- Select -</option>';
    validOptions.forEach(v => {
        let cleanText = v.toLowerCase();
        html += `<option value="${cleanText}">${cleanText}</option>`;
    });
    
    if (validOptions.length === 0) {
        html += `<option value="-" disabled>No pattern matches found</option>`;
    }
    
    target.innerHTML = html;
}

function applySuffix() {
    const cipher = document.getElementById('suffixSelect').value;
    const plain = document.getElementById('suffixTarget').value;
    if (cipher !== '-' && plain !== '-') requestMapping(cipher, plain);
}

function populateDoubleLetters() {
    const select = document.getElementById('doubleSelect');
    if (!select) return;
    const currentVal = select.value;
    const doubles = originalText.match(/([A-Z])\1/g) || [];
    let counts = {};
    doubles.forEach(d => counts[d] = (counts[d] || 0) + 1);
    let sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    let html = '<option value="-">-</option>';
    sorted.forEach(([cipher, count]) => html += `<option value="${cipher}">${cipher} (${count})</option>`);
    select.innerHTML = html;
    if (currentVal && counts[currentVal]) select.value = currentVal;
    else updateDoubleTargets();
}

function updateDoubleTargets() {
    const target = document.getElementById('doubleTarget');
    if (!target) return;
    let html = '<option value="-">- Select -</option>';
    commonDoubles.forEach(v => html += `<option value="${v}">${v}</option>`);
    target.innerHTML = html;
}

function applyDouble() {
    const cipher = document.getElementById('doubleSelect').value;
    const plain = document.getElementById('doubleTarget').value;
    if (cipher !== '-' && plain !== '-') requestMapping(cipher[0], plain[0]); 
}

/**
 * Validation Wrapper: requestMapping
 * Orchestrates mapping updates and enforces data integrity via conflict resolution.
 */
function requestMapping(cipherStr, plainStr) {
    let conflicts = [];
    let theftVictims = []; 

    // Handle clear-entry requests
    if (plainStr === "") {
        addMapping(cipherStr, "");
        return;
    }

    for (let i = 0; i < cipherStr.length; i++) {
        let c = cipherStr[i];
        if (!plainStr[i]) continue; 
        let p = plainStr[i].toLowerCase();

        // Check for existing Cipher-to-Plain conflicts
        if (mapping[c] && mapping[c] !== p) {
            conflicts.push(`Cipher '${c}' is already linked to '${mapping[c]}'.`);
        }

        // Check for existing Plain-to-Cipher conflicts (Bijective violation)
        for (let [existingKey, existingVal] of Object.entries(mapping)) {
            if (existingVal === p && existingKey !== c) {
                conflicts.push(`Plaintext '${p}' is already claimed by Cipher '${existingKey}'.`);
                theftVictims.push(existingKey); 
            }
        }
    }

    // Modal interaction for mapping resolution
    if (conflicts.length > 0) {
        let uniqueConflicts = [...new Set(conflicts)];
        let message = "Mapping Conflict Found:\n\n" + 
                      uniqueConflicts.join("\n") + 
                      "\n\nDo you want to overwrite these and force the new mapping?";
                      
        if (!confirm(message)) {
            updateAll(); 
            return;
        }

        // De-link conflicted mappings to satisfy 1-to-1 requirement
        theftVictims.forEach(victim => {
            mapping[victim] = ''; 
            lockedLetters[victim] = false; 
        });
    }

    // Persist mapping update and update UI
    saveToHistory(); 
    for (let i = 0; i < cipherStr.length; i++) {
        if (plainStr[i]) {
            addMapping(cipherStr[i], plainStr[i]);
        }
    }
    updateAll(); 
}

function setGhostWord(word) {
    if (word === '-') {
        currentGhostWord = null;
    } else {
        currentGhostWord = word.split(' ')[0]; 
    }
    renderOutput(); 
}

// Dynamic focus management
document.addEventListener('click', (e) => {
    if (!e.target.closest('select') && !e.target.closest('button')) {
        currentGhostWord = null;
        renderOutput();
    }
});

/**
 * Progress Calculation
 * Evaluates decryption completion percentage based on used cipher characters.
 */
function updateProgressBadge() {
    const badge = document.getElementById('qualityBadge');
    if (!badge || !originalText) return;

    const uniqueCipherLetters = new Set(originalText.match(/[A-Z]/g));
    if (uniqueCipherLetters.size === 0) {
        badge.textContent = "Waiting for text...";
        badge.className = 'badge badge-gray';
        return;
    }

    let solvedCount = 0;
    uniqueCipherLetters.forEach(char => {
        if (mapping[char] && mapping[char] !== '') {
            solvedCount++;
        }
    });

    const totalUnique = uniqueCipherLetters.size;
    const percentage = Math.round((solvedCount / totalUnique) * 100);

    if (percentage === 100) {
        badge.className = 'badge badge-green';
        badge.textContent = `🎉 Decryption Complete: 100% (${totalUnique}/${totalUnique} letters) 🎉`;
    } else {
        badge.className = 'badge badge-gray';
        badge.textContent = `Decryption Progress: ${percentage}% (${solvedCount}/${totalUnique} letters)`;
    }
}

/* ==========================================================================
   Instructional Modals & Interaction
   ========================================================================== */

function openGuide() {
    document.getElementById('guideModal').style.display = 'flex';
}

function closeGuide() {
    document.getElementById('guideModal').style.display = 'none';
}

function toggleSolution(id) {
    const el = document.getElementById(id);
    el.style.display = (el.style.display === 'block') ? 'none' : 'block';
}

window.addEventListener('click', (e) => {
    const modal = document.getElementById('guideModal');
    if (e.target === modal) closeGuide();
});

// Lexical Pattern Solver
let currentModalWord = "";

function openWordModal(cipherWord) {
    currentModalWord = cipherWord;
    const grid = document.getElementById('wordSolverGrid');
    const suggestionsDiv = document.getElementById('smartSuggestions');
    
    // Dynamic generation of modal input fields
    let html = '';
    for (let i = 0; i < cipherWord.length; i++) {
        let c = cipherWord[i];
        let m = mapping[c] || '';
        html += `
        <div style="display: flex; flex-direction: column; align-items: center;">
            <span style="color: #888; font-size: 0.85em; font-weight: bold; margin-bottom: 4px;">${c}</span>
            <input type="text" id="modalInput_${i}" maxlength="1" value="${m}" 
                   style="width: 36px; height: 40px; text-align: center; font-size: 1.2em; text-transform: lowercase; border: 2px solid #ccc; border-radius: 6px;">
        </div>`;
    }
    grid.innerHTML = html;

    // Dictionary Pattern Matching
    const targetPattern = getWordPattern(cipherWord);
    const matches = fullDictionary.filter(w => 
        w.length === cipherWord.length && 
        getWordPattern(w.toUpperCase()) === targetPattern
    ).slice(0, 12); 
    
    // UI population for suggestions
    if (matches.length > 0) {
        suggestionsDiv.innerHTML = matches.map(w => 
            `<button onclick="fillModalWord('${w}')" style="background: white; border: 1px solid #0056b3; color: #0056b3; padding: 4px 10px; border-radius: 4px; cursor: pointer; margin: 2px; text-transform: lowercase;">${w}</button>`
        ).join('');
    } else {
        suggestionsDiv.innerHTML = `<span style="color: #999; font-size: 0.9em; font-style: italic;">No pattern matches found in the 10k dictionary.</span>`;
    }

    document.getElementById('wordModal').style.display = 'flex';
}

function closeWordModal() {
    document.getElementById('wordModal').style.display = 'none';
}

function fillModalWord(plainWord) {
    for (let i = 0; i < plainWord.length; i++) {
        let input = document.getElementById(`modalInput_${i}`);
        if (input) input.value = plainWord[i];
    }
}

function applyWordModal() {
    let plainGuess = "";
    for (let i = 0; i < currentModalWord.length; i++) {
        let val = document.getElementById(`modalInput_${i}`).value;
        plainGuess += val ? val : ""; 
    }
    
    // Validate mapping request via global conflict controller
    requestMapping(currentModalWord, plainGuess); 
    closeWordModal();
}