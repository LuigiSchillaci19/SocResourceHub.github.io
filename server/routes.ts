import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";

export async function registerRoutes(app: Express): Promise<Server> {
  // API routes for SOC resource hub
  // Currently not needed as all data is available statically in the frontend
  // This can be extended in the future for storing user preferences, custom links, etc.
  
  app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy' });
  });

  const httpServer = createServer(app);

  return httpServer;
}
