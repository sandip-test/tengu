import { InferSelectModel, relations } from 'drizzle-orm';
import { pgTable, uuid, timestamp, boolean } from 'drizzle-orm/pg-core';
import { users } from './user.entity';
export const admins = pgTable('admins', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id')
    .references(() => users.id, { onDelete: 'cascade' })
    .unique()
    .notNull(),
  isActive: boolean('is_active').default(true),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
  // adminLevel: varchar('admin_level', { length: 20 }).default('SCHOOL'), // SCHOOL, DISTRICT, etc.
  // permissions: jsonb('permissions'),
});
export const adminsRelations = relations(admins, ({ one }) => ({
  user: one(users, {
    fields: [admins.userId],
    references: [users.id],
  }),
}));

export type ADMINS = InferSelectModel<typeof admins>;
