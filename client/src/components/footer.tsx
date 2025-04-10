export function Footer() {
  return (
    <footer className="bg-primary-dark text-white py-4 mt-8">
      <div className="container mx-auto px-4">
        <div className="flex flex-col md:flex-row justify-between items-center">
          <div className="mb-4 md:mb-0">
            <p className="text-sm opacity-70">SOC Resource Hub - Centralized Security Operations Resources</p>
          </div>
          <div className="flex space-x-4">
            <a href="#" className="text-white/70 hover:text-white text-sm">Privacy Policy</a>
            <a href="#" className="text-white/70 hover:text-white text-sm">Terms of Use</a>
            <a href="#" className="text-white/70 hover:text-white text-sm">Contact</a>
          </div>
        </div>
      </div>
    </footer>
  );
}
