
const categories = [
    {
        title: "Threat Hunting",
        sections: [
            {
                title: "SIEM & Analytics",
                tools: [
                    { name: "Elastic SIEM", url: "https://www.elastic.co/security" },
                    { name: "Splunk ES", url: "https://www.splunk.com/en_us/cybersecurity.html" },
                    { name: "TH Playbook", url: "https://github.com/OTRF/ThreatHunter-Playbook" }
                ]
            },
            {
                title: "SIEM Rule Creation",
                tools: [
                    { name: "Sigma Rules", url: "https://github.com/SigmaHQ/sigma" },
                    { name: "SOC Prime", url: "https://socprime.com/search-engine" },
                    { name: "Elastic Rules", url: "https://github.com/elastic/detection-rules" }
                ]
            }
        ]
    }
];

function createToolCard(tool) {
    return `
        <div class="tool-card">
            <a href="${tool.url}" class="tool-link" target="_blank" rel="noopener noreferrer">
                ${tool.name}
            </a>
        </div>
    `;
}

function createSection(section) {
    return `
        <div class="section">
            <h2>${section.title}</h2>
            <div class="tools-grid">
                ${section.tools.map(tool => createToolCard(tool)).join('')}
            </div>
        </div>
    `;
}

function renderCategories() {
    const categoriesContainer = document.getElementById('categories');
    const content = categories.map(category => `
        <div class="category">
            <h1>${category.title}</h1>
            ${category.sections.map(section => createSection(section)).join('')}
        </div>
    `).join('');
    
    categoriesContainer.innerHTML = content;
}

document.addEventListener('DOMContentLoaded', renderCategories);
