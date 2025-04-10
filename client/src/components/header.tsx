import { useState, useEffect } from "react";
import { useTheme } from "@/components/theme-provider";
import { Input } from "@/components/ui/input";

interface HeaderProps {
  onSearch: (term: string) => void;
}

export function Header({ onSearch }: HeaderProps) {
  const { theme, setTheme } = useTheme();
  const [searchTerm, setSearchTerm] = useState("");
  
  const handleSearch = (e: React.ChangeEvent<HTMLInputElement>) => {
    const term = e.target.value;
    setSearchTerm(term);
    onSearch(term);
  };
  
  const toggleTheme = () => {
    setTheme(theme === 'dark' ? 'light' : 'dark');
  };
  
  useEffect(() => {
    // Load Remix icons
    const link = document.createElement('link');
    link.href = 'https://cdn.jsdelivr.net/npm/remixicon@3.5.0/fonts/remixicon.css';
    link.rel = 'stylesheet';
    document.head.appendChild(link);
    
    return () => {
      document.head.removeChild(link);
    };
  }, []);
  
  return (
    <header className="bg-primary dark:bg-primary sticky top-0 z-50 shadow-lg py-4">
      <div className="container mx-auto px-4 flex justify-between items-center">
        <div className="flex items-center">
          <i className="ri-shield-keyhole-line text-3xl text-white mr-2"></i>
          <h1 className="text-xl md:text-2xl font-bold text-white">SOC Resource Hub</h1>
        </div>
        <div className="flex items-center space-x-4">
          <div className="relative">
            <Input
              type="text"
              id="search"
              value={searchTerm}
              onChange={handleSearch}
              placeholder="Search resources..."
              className="search-input bg-white/10 text-white rounded-lg py-2 px-4 pl-10 w-32 md:w-64 border border-white/20 focus:outline-none focus:border-secondary placeholder:text-white/70"
            />
            <i className="ri-search-line absolute left-3 top-2.5 text-white/70"></i>
          </div>
          <button 
            onClick={toggleTheme}
            className="p-2 rounded-full hover:bg-white/10"
            aria-label="Toggle dark/light mode"
          >
            <i className={`${theme === 'dark' ? 'ri-sun-line' : 'ri-moon-line'} text-xl text-white`}></i>
          </button>
        </div>
      </div>
    </header>
  );
}
