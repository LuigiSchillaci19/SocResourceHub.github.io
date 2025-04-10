import { type CategoryResource, type InsertCategoryResource } from "@shared/schema";

// Storage interface for SOC resource hub
export interface IStorage {
  getAllResources(): Promise<CategoryResource[]>;
  getResourcesByCategory(category: string): Promise<CategoryResource[]>;
  addResource(resource: InsertCategoryResource): Promise<CategoryResource>;
}

export class MemStorage implements IStorage {
  private resources: Map<number, CategoryResource>;
  currentId: number;

  constructor() {
    this.resources = new Map();
    this.currentId = 1;
  }

  async getAllResources(): Promise<CategoryResource[]> {
    return Array.from(this.resources.values());
  }

  async getResourcesByCategory(category: string): Promise<CategoryResource[]> {
    return Array.from(this.resources.values()).filter(
      (resource) => resource.category.toLowerCase() === category.toLowerCase()
    );
  }

  async addResource(resource: InsertCategoryResource): Promise<CategoryResource> {
    const id = this.currentId++;
    const newResource: CategoryResource = { ...resource, id };
    this.resources.set(id, newResource);
    return newResource;
  }
}

export const storage = new MemStorage();
