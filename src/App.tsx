
import { useState } from 'react';
import { CategorySection } from './components/CategorySection';
import { Search } from './components/Search';
import { categories } from './data/categories';
import './styles.css';

export default function App() {
  const [searchTerm, setSearchTerm] = useState('');
  
  const filteredCategories = categories.map(category => ({
    ...category,
    sections: category.sections.map(section => ({
      ...section,
      tools: section.tools.filter(tool => 
        tool.name.toLowerCase().includes(searchTerm.toLowerCase())
      )
    })).filter(section => section.tools.length > 0)
  })).filter(category => category.sections.length > 0);

  return (
    <div className="app-container">
      <header className="header">
        <h1>Security Tools Hub</h1>
        <Search onSearch={setSearchTerm} />
      </header>
      <main className="main-content">
        {filteredCategories.map((category, index) => (
          <CategorySection key={index} {...category} />
        ))}
      </main>
    </div>
  );
}
