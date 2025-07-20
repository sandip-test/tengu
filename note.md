# Authentication Flow & Table Structure Design

## Recommended Approach: Hybrid Pattern

Based on your existing schema, I recommend continuing with your current approach but with some enhancements:

### 1. **Main Users Table + Role-Specific Tables**

- Keep the `users` table as the central authentication table
- Create role-specific tables (`teachers`, `students`, `admins`) for role-specific data
- This provides flexibility for bulk operations while maintaining data integrity

### 2. **Why This Approach Works Best:**

#### ✅ **Advantages:**

- **Bulk Operations**: Easy to create students in bulk - create user records first, then student records
- **Role-Specific Data**: Each role can have specific fields without cluttering the main table
- **Authentication Simplicity**: Single login flow using the users table
- **Data Integrity**: Referential integrity between users and role tables
- **Scalability**: Easy to extend with new roles or role-specific features
- **Performance**: Indexed properly for fast lookups

#### ❌ **Alternative Approaches (Why Not):**

- **Single Users Table Only**: Would require many nullable columns for role-specific data
- **Separate Tables Only**: Would complicate authentication and duplicate common fields
- **Table Per Role**: Would make cross-role queries and reporting difficult

## Recommended Schema Structure

```typescript
// Your existing users table (keep as is)
export const users = pgTable('users', {
  // ... your existing fields
});

// Your existing teachers table (keep as is)
export const teachers = pgTable('teachers', {
  // ... your existing fields
});

// Add students table (similar to teachers)
export const students = pgTable('students', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id')
    .references(() => users.id, { onDelete: 'cascade' })
    .unique()
    .notNull(),
  studentId: varchar('student_id', { length: 50 }).unique().notNull(), // Roll number
  admissionDate: date('admission_date').notNull(),
  guardianName: varchar('guardian_name', { length: 100 }),
  guardianPhone: varchar('guardian_phone', { length: 20 }),
  guardianEmail: varchar('guardian_email', { length: 255 }),
  bloodGroup: varchar('blood_group', { length: 5 }),
  emergencyContact: varchar('emergency_contact', { length: 20 }),
  previousSchool: varchar('previous_school', { length: 200 }),
  isActive: boolean('is_active').default(true),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

// Add admins table for completeness
export const admins = pgTable('admins', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id')
    .references(() => users.id, { onDelete: 'cascade' })
    .unique()
    .notNull(),
  adminLevel: varchar('admin_level', { length: 20 }).default('SCHOOL'), // SCHOOL, DISTRICT, etc.
  permissions: jsonb('permissions'), // Specific permissions
  isActive: boolean('is_active').default(true),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});
```

## Authentication Flow Design

### 1. **Login Process**

```typescript
// Single authentication endpoint
POST /api/auth/login
{
  "email": "user@example.com",
  "password": "password123"
}

// Response includes role information
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "role": "STUDENT",
    "firstName": "John",
    "lastName": "Doe"
  },
  "token": "jwt_token",
  "redirectTo": "/dashboard/student" // Role-based redirect
}
```

### 2. **Role Detection & Redirection**

```typescript
// Middleware checks role and redirects appropriately
if (user.role === 'ADMIN') redirect('/dashboard/admin');
if (user.role === 'TEACHER') redirect('/dashboard/teacher');
if (user.role === 'STUDENT') redirect('/dashboard/student');
```

### 3. **Data Fetching Strategy**

```typescript
// For each role, fetch additional data as needed
const getCompleteUserData = async (userId: string, role: UserRole) => {
  const baseUser = await getUserById(userId);

  switch (role) {
    case 'ADMIN':
      const adminData = await getAdminByUserId(userId);
      return { ...baseUser, adminDetails: adminData };

    case 'TEACHER':
      const teacherData = await getTeacherByUserId(userId);
      return { ...baseUser, teacherDetails: teacherData };

    case 'STUDENT':
      const studentData = await getStudentByUserId(userId);
      return { ...baseUser, studentDetails: studentData };
  }
};
```

## Bulk Student Creation Strategy

### 1. **Admin Interface for Bulk Upload**

```typescript
// CSV/Excel upload endpoint
POST /api/admin/students/bulk-create
Content-Type: multipart/form-data

// Expected CSV format:
// firstName,lastName,email,dateOfBirth,guardianName,guardianPhone,class,section
// John,Doe,john@email.com,2010-05-15,Jane Doe,1234567890,Grade 5,A
```

### 2. **Bulk Creation Process**

```typescript
const bulkCreateStudents = async (studentsData: StudentBulkData[]) => {
  return await db.transaction(async (tx) => {
    const results = [];

    for (const studentData of studentsData) {
      // 1. Create user record
      const user = await tx
        .insert(users)
        .values({
          email: studentData.email,
          password: await hashPassword(generateTemporaryPassword()),
          role: 'STUDENT',
          firstName: studentData.firstName,
          lastName: studentData.lastName,
          dateOfBirth: studentData.dateOfBirth,
          // ... other user fields
        })
        .returning();

      // 2. Create student record
      const student = await tx
        .insert(students)
        .values({
          userId: user[0].id,
          studentId: generateStudentId(),
          admissionDate: new Date(),
          guardianName: studentData.guardianName,
          guardianPhone: studentData.guardianPhone,
          // ... other student fields
        })
        .returning();

      // 3. Enroll in class/section if specified
      if (studentData.classId && studentData.sectionId) {
        await tx.insert(enrollments).values({
          studentId: student[0].id,
          classId: studentData.classId,
          sectionId: studentData.sectionId,
          academicYearId: getCurrentAcademicYearId(),
        });
      }

      results.push({ user: user[0], student: student[0] });
    }

    return results;
  });
};
```

### 3. **Password Management for Bulk Users**

```typescript
// Generate temporary passwords and send via email/SMS
const handleBulkPasswordDistribution = async (createdStudents: any[]) => {
  for (const { user, student } of createdStudents) {
    const tempPassword = generateTemporaryPassword();

    // Send credentials via email to guardian
    await sendWelcomeEmail({
      to: student.guardianEmail || user.email,
      studentName: `${user.firstName} ${user.lastName}`,
      studentId: student.studentId,
      email: user.email,
      tempPassword: tempPassword,
    });

    // Mark user as requiring password change on first login
    await updateUser(user.id, {
      mustChangePassword: true,
      passwordResetToken: generateResetToken(),
    });
  }
};
```

## Database Migration Strategy

### 1. **Add Missing Tables**

```sql
-- Add students table
CREATE TABLE students (
  -- ... fields as defined above
);

-- Add admins table
CREATE TABLE admins (
  -- ... fields as defined above
);

-- Add enrollment table (if not exists)
CREATE TABLE enrollments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id UUID REFERENCES students(id) ON DELETE CASCADE,
  class_id UUID REFERENCES classes(id) ON DELETE CASCADE,
  section_id UUID REFERENCES sections(id) ON DELETE CASCADE,
  academic_year_id UUID REFERENCES academic_years(id) ON DELETE CASCADE,
  enrollment_date DATE NOT NULL,
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);
```

### 2. **Create Indexes for Performance**

```sql
-- Students table indexes
CREATE INDEX idx_students_student_id ON students(student_id);
CREATE INDEX idx_students_is_active ON students(is_active);
CREATE INDEX idx_students_admission_date ON students(admission_date);

-- Enrollments indexes
CREATE INDEX idx_enrollments_student_id ON enrollments(student_id);
CREATE INDEX idx_enrollments_class_section ON enrollments(class_id, section_id);
CREATE INDEX idx_enrollments_academic_year ON enrollments(academic_year_id);
```

## Security Considerations

### 1. **Role-Based Access Control**

```typescript
// Middleware to check permissions
const requireRole = (allowedRoles: UserRole[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const userRole = req.user.role;
    if (!allowedRoles.includes(userRole)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

// Usage
app.post(
  '/api/admin/students/bulk-create',
  authenticate,
  requireRole(['ADMIN']),
  bulkCreateStudentsHandler,
);
```

### 2. **Data Validation**

```typescript
// Validate bulk student data
const validateStudentData = (data: any[]) => {
  const errors = [];

  data.forEach((student, index) => {
    if (!student.email || !isValidEmail(student.email)) {
      errors.push(`Row ${index + 1}: Invalid email`);
    }
    if (!student.firstName || !student.lastName) {
      errors.push(`Row ${index + 1}: Name is required`);
    }
    // ... more validations
  });

  return errors;
};
```

## Summary

✅ **Recommended Approach:**

- Keep your current `users` table structure
- Add `students` and `admins` tables (similar to your `teachers` table)
- Use single authentication flow with role-based redirection
- Implement bulk creation using database transactions
- Handle temporary password generation and distribution

This approach gives you the flexibility for bulk operations while maintaining data integrity and a clean authentication flow.
