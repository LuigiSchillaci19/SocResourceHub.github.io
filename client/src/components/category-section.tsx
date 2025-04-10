import { useState } from "react";
import { CategoryProps } from "@/lib/utils";

interface CategorySectionProps {
  category: CategoryProps;
  isExpanded?: boolean;
}

export function CategorySection({ category, isExpanded = true }: CategorySectionProps) {
  const [expanded, setExpanded] = useState(isExpanded);
  
  return (
    <section className="category-section bg-card dark:bg-neutral-dark/50 rounded-xl shadow-lg overflow-hidden">
      <div className={`category-header ${category.borderColor} pl-4 py-4 bg-card/50 dark:bg-neutral-dark flex justify-between items-center`}>
        <div className="flex items-center space-x-3">
          <i className={`${category.icon} text-xl ${category.borderColor.replace('border-', 'text-')}`}></i>
          <h3 className="text-xl font-bold">{category.title}</h3>
        </div>
        <button 
          className="category-toggle p-2 mr-4 rounded-full hover:bg-accent dark:hover:bg-neutral-dark"
          onClick={() => setExpanded(!expanded)}
          aria-label={expanded ? "Collapse section" : "Expand section"}
        >
          <i className={`${expanded ? 'ri-arrow-down-s-line' : 'ri-arrow-right-s-line'} text-xl`}></i>
        </button>
      </div>
      
      {expanded && (
        <div className="category-content p-4">
          {category.sections.map((section, sectionIndex) => (
            <div key={sectionIndex} className={sectionIndex < category.sections.length - 1 ? "mb-4" : ""}>
              <div className="text-sm text-muted-foreground dark:text-neutral-light/70 mb-2">{section.title}</div>
              <div className={`grid grid-cols-2 md:grid-cols-3 gap-2 ${section.title.includes('Documentation') || section.title.includes('Resources') || section.title.includes('IOC Tools') || section.title.includes('Learning') ? 'grid-cols-1' : ''}`}>
                {section.tools.map((tool, toolIndex) => (
                  <a 
                    key={toolIndex}
                    href={tool.url} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className={`tool-link tool-card bg-accent dark:bg-neutral-dark/90 hover:bg-primary/10 dark:hover:bg-primary-dark/30 p-2 rounded ${
                      tool.icon ? 'flex items-center justify-between px-3' : 'text-center'
                    } font-mono text-sm`}
                  >
                    <span>{tool.name}</span>
                    {tool.icon && <i className={tool.icon}></i>}
                  </a>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
