
const categories = [
    {
        title: "Threat Hunting",
        icon: "fa-radar",
        sections: [
            {
                title: "SIEM & Analytics",
                tools: [
                    { name: "Elastic SIEM", url: "https://www.elastic.co/security", icon: "fa-chart-line" },
                    { name: "Splunk ES", url: "https://www.splunk.com/en_us/cybersecurity.html", icon: "fa-database" },
                    { name: "TH Playbook", url: "https://github.com/OTRF/ThreatHunter-Playbook", icon: "fa-book" }
                ]
            },
            {
                title: "SIEM Rule Creation",
                tools: [
                    { name: "Sigma Rules", url: "https://github.com/SigmaHQ/sigma", icon: "fa-shield" },
                    { name: "SOC Prime", url: "https://socprime.com/search-engine", icon: "fa-magnifying-glass" },
                    { name: "Elastic Rules", url: "https://github.com/elastic/detection-rules", icon: "fa-list" }
                ]
            }
        ]
    },
    {
        title: "Email Analysis",
        icon: "fa-envelope",
        sections: [
            {
                title: "Phishing Analysis",
                tools: [
                    { name: "PhishTool", url: "https://www.phishtool.com", icon: "fa-fish" },
                    { name: "PhishTank", url: "https://phishtank.org", icon: "fa-shield" },
                    { name: "URLScan.io", url: "https://urlscan.io", icon: "fa-link" }
                ]
            }
        ]
    }
];

function createToolCard(tool) {
    return `
        <div class="tool-card">
            <a href="${tool.url}" class="tool-link" target="_blank" rel="noopener noreferrer">
                <i class="fas ${tool.icon}"></i>
                <span>${tool.name}</span>
            </a>
        </div>
    `;
}

function renderCategories(searchTerm = '') {
    const categoriesContainer = document.getElementById('categories');
    const content = categories.map(category => {
        const filteredSections = category.sections.map(section => {
            const filteredTools = section.tools.filter(tool =>
                tool.name.toLowerCase().includes(searchTerm.toLowerCase())
            );
            return filteredTools.length > 0 ? { ...section, tools: filteredTools } : null;
        }).filter(Boolean);

        if (filteredSections.length === 0) return '';

        return `
            <div class="category">
                <h2><i class="fas ${category.icon}"></i> ${category.title}</h2>
                ${filteredSections.map(section => `
                    <div class="section">
                        <h3>${section.title}</h3>
                        <div class="tools-grid">
                            ${section.tools.map(tool => createToolCard(tool)).join('')}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }).join('');
    
    categoriesContainer.innerHTML = content;
}

document.addEventListener('DOMContentLoaded', () => {
    renderCategories();
    
    const searchInput = document.getElementById('searchInput');
    searchInput.addEventListener('input', (e) => {
        renderCategories(e.target.value);
    });
});
