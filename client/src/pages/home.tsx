import { useState } from "react";
import { Header } from "@/components/header";
import { CategorySection } from "@/components/category-section";
import { Footer } from "@/components/footer";
import { allCategories, CategoryProps } from "@/lib/utils";
import { Button } from "@/components/ui/button";

export default function Home() {
  const [searchTerm, setSearchTerm] = useState("");
  const [expandAll, setExpandAll] = useState(true);
  
  const handleSearch = (term: string) => {
    setSearchTerm(term.toLowerCase());
    // If search is active, make sure all sections are expanded
    if (term.trim().length > 0) {
      setExpandAll(true);
    }
  };
  
  // Filter categories based on search term
  const filteredCategories = allCategories.map(category => {
    if (searchTerm === "") return category;
    
    // Deep copy the category to modify sections without affecting the original
    const filteredCategory: CategoryProps = {
      ...category,
      sections: category.sections.map(section => ({
        ...section,
        tools: section.tools.filter(tool => 
          tool.name.toLowerCase().includes(searchTerm)
        )
      })).filter(section => section.tools.length > 0)
    };
    
    return filteredCategory;
  }).filter(category => category.sections.length > 0);
  
  const toggleAllSections = (expanded: boolean) => {
    setExpandAll(expanded);
  };
  
  return (
    <div className="min-h-screen flex flex-col">
      <Header onSearch={handleSearch} />
      
      <main className="container mx-auto px-4 py-8 flex-grow">
        <div className="flex justify-between items-center mb-8">
          <h2 className="text-2xl font-bold">Security Operations Categories</h2>
          <div className="flex items-center space-x-2">
            <Button 
              variant="default" 
              size="sm" 
              className="flex items-center space-x-1"
              onClick={() => toggleAllSections(true)}
            >
              <i className="ri-expand-height-line mr-1"></i>
              <span>Expand All</span>
            </Button>
            <Button 
              variant="secondary" 
              size="sm" 
              className="flex items-center space-x-1"
              onClick={() => toggleAllSections(false)}
            >
              <i className="ri-contract-height-line mr-1"></i>
              <span>Collapse All</span>
            </Button>
          </div>
        </div>
        
        <div id="category-grid" className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredCategories.map((category, index) => (
            <CategorySection 
              key={index} 
              category={category} 
              isExpanded={expandAll}
            />
          ))}
        </div>
        
        {filteredCategories.length === 0 && (
          <div className="flex flex-col items-center justify-center py-16">
            <i className="ri-search-eye-line text-5xl text-muted-foreground mb-4"></i>
            <h3 className="text-xl font-semibold text-foreground mb-2">No resources found</h3>
            <p className="text-muted-foreground">Try a different search term</p>
          </div>
        )}
      </main>
      
      <Footer />
    </div>
  );
}
