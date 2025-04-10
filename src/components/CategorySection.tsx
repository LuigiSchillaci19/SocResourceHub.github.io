
import { useState } from 'react';

interface Tool {
  name: string;
  url: string;
  icon?: string;
}

interface Section {
  title: string;
  tools: Tool[];
}

interface CategoryProps {
  title: string;
  icon: string;
  sections: Section[];
}

export function CategorySection({ title, icon, sections }: CategoryProps) {
  const [isExpanded, setIsExpanded] = useState(true);

  return (
    <div className="category">
      <div className="category-header" onClick={() => setIsExpanded(!isExpanded)}>
        <i className={`ri-${icon}`}></i>
        <h2>{title}</h2>
        <i className={`ri-arrow-${isExpanded ? 'down' : 'right'}-s-line`}></i>
      </div>
      {isExpanded && (
        <div className="category-content">
          {sections.map((section, index) => (
            <div key={index} className="section">
              <h3>{section.title}</h3>
              <div className="tools-grid">
                {section.tools.map((tool, toolIndex) => (
                  <a
                    key={toolIndex}
                    href={tool.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="tool-card"
                  >
                    <span>{tool.name}</span>
                    {tool.icon && <i className={`ri-${tool.icon}`}></i>}
                  </a>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
