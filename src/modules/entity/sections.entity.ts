import {
  integer,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';
import { classes } from './class.entity';

export const sections = pgTable(
  'sections',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    name: varchar('name', { length: 50 }).notNull(), // e.g., "A", "B", "C"
    classId: uuid('class_id')
      .references(() => classes.id, { onDelete: 'cascade' })
      .notNull(),
    capacity: integer('capacity').default(30),
    description: text('description'),
    createdAt: timestamp('created_at').defaultNow(),
    updatedAt: timestamp('updated_at').defaultNow(),
  },
  (table) => [
    uniqueIndex('sections_name_class_idx').on(table.name, table.classId),
  ],
);
