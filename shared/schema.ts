import { pgTable, text, serial, varchar } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const categoryResources = pgTable("category_resources", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  category: text("category").notNull(),
  subcategory: text("subcategory").notNull(),
  url: text("url").notNull(),
  icon: text("icon"),
  description: text("description"),
});

export const insertCategoryResourceSchema = createInsertSchema(categoryResources).pick({
  name: true,
  category: true,
  subcategory: true,
  url: true,
  icon: true,
  description: true,
});

export type InsertCategoryResource = z.infer<typeof insertCategoryResourceSchema>;
export type CategoryResource = typeof categoryResources.$inferSelect;
