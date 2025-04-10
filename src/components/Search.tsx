
interface SearchProps {
  onSearch: (term: string) => void;
}

export function Search({ onSearch }: SearchProps) {
  return (
    <div className="search-container">
      <input
        type="text"
        placeholder="Search tools..."
        onChange={(e) => onSearch(e.target.value)}
        className="search-input"
      />
      <i className="ri-search-line"></i>
    </div>
  );
}
