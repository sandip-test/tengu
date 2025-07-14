# 🎓 Student Management System (SMS)

A comprehensive Student Management System built with **NestJS**, **TypeScript**, **Drizzle ORM**, and **PostgreSQL**. This system provides a robust platform for managing students, teachers, academic years, classes, and sections in educational institutions.

## 📋 Table of Contents

- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Environment Setup](#-environment-setup)
- [Database Setup](#-database-setup)
- [Running the Application](#-running-the-application)
- [API Documentation](#-api-documentation)
- [Project Structure](#-project-structure)
- [Available Scripts](#-available-scripts)
- [Database Schema](#-database-schema)
- [Authentication](#-authentication)
- [Testing](#-testing)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

- **User Management**: Admin, Teacher, and Student role-based access control
- **Authentication & Authorization**: JWT-based secure authentication system
- **Academic Management**: Manage academic years, classes, and sections
- **Student Management**: Complete student profile management
- **Teacher Management**: Teacher profile and assignment management
- **API Documentation**: Auto-generated Swagger/OpenAPI documentation
- **Database Management**: Type-safe database operations with Drizzle ORM
- **Validation**: Comprehensive input validation with class-validator
- **Security**: Password hashing with bcrypt and secure JWT tokens

## 🚀 Tech Stack

### Backend

- **Framework**: [NestJS](https://nestjs.com/) - Progressive Node.js framework
- **Language**: [TypeScript](https://www.typescriptlang.org/) - Type-safe JavaScript
- **Database**: [PostgreSQL](https://www.postgresql.org/) - Powerful relational database
- **ORM**: [Drizzle ORM](https://orm.drizzle.team/) - Type-safe SQL toolkit
- **Authentication**: [JWT](https://jwt.io/) - JSON Web Tokens
- **Validation**: [class-validator](https://github.com/typestack/class-validator) - Decorator-based validation
- **Documentation**: [Swagger/OpenAPI](https://swagger.io/) - API documentation

### Development Tools

- **Package Manager**: [pnpm](https://pnpm.io/) - Fast, disk space efficient package manager
- **Code Quality**: [ESLint](https://eslint.org/) + [Prettier](https://prettier.io/)
- **Testing**: [Jest](https://jestjs.io/) - JavaScript testing framework
- **Database Management**: [Drizzle Kit](https://orm.drizzle.team/kit-docs/overview) - Database migrations and introspection

## 📋 Prerequisites

Before running this application, make sure you have the following installed:

- **Node.js** (v18 or higher)
- **pnpm** (recommended) or npm/yarn
- **PostgreSQL** (v12 or higher)
- **Git**

## 🛠 Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/sayapatriGroup/SMS.git
   cd SMS
   ```

2. **Install dependencies**
   ```bash
   pnpm install
   ```

## 🔧 Environment Setup

1. **Create environment file**

   ```bash
   cp .env.example .env
   ```

2. **Configure your environment variables**

   ```env
   # Database Configuration
   DATABASE_URL="postgresql://username:password@localhost:5432/sms_db"

   # JWT Configuration
   JWT_SECRET="your-super-secure-jwt-secret-key"

   # Application Configuration
   PORT=3000
   NODE_ENV=development
   ```

## 🗄️ Database Setup

1. **Create PostgreSQL database**

   ```sql
   CREATE DATABASE sms_db;
   ```

2. **Generate and run migrations**

   ```bash
   # Generate migration files
   pnpm run db:generate

   # Apply migrations to database
   pnpm run db:migrate
   ```

3. **Open Drizzle Studio (optional)**
   ```bash
   pnpm run db:studio
   ```

## 🚀 Running the Application

### Development Mode

```bash
# Watch mode with hot reload
pnpm run dev

# Debug mode
pnpm run start:debug
```

### Production Mode

```bash
# Build the application
pnpm run build

# Start production server
pnpm run start:prod
```

The application will be available at `http://localhost:3000`

## 📚 API Documentation

Once the application is running, you can access the interactive API documentation:

- **Swagger UI**: `http://localhost:3000/api`
- **OpenAPI JSON**: `http://localhost:3000/api-json`

## 📁 Project Structure

```
src/
├── common/                 # Shared utilities and decorators
│   ├── decorators/        # Custom decorators
│   ├── guards/            # Authentication guards
│   ├── interceptors/      # Response interceptors
│   └── validators/        # Custom validators
├── db/                    # Database configuration
│   ├── index.ts          # Database connection
│   └── schema.ts         # Database schema exports
├── drizzle/              # Database migrations
├── lib/                  # Utility libraries
│   ├── auth.lib.ts       # Authentication utilities
│   └── types.ts          # Type definitions
├── modules/              # Feature modules
│   ├── entities/         # Database entities
│   └── users/            # User module
│       ├── dto/          # Data Transfer Objects
│       ├── users.controller.ts
│       ├── users.service.ts
│       └── users.module.ts
├── app.module.ts         # Root application module
└── main.ts              # Application entry point
```

## 📜 Available Scripts

| Script                | Description                              |
| --------------------- | ---------------------------------------- |
| `pnpm run dev`        | Start development server with hot reload |
| `pnpm run build`      | Build the application for production     |
| `pnpm run start`      | Start the application                    |
| `pnpm run start:prod` | Start production server                  |
| `pnpm run lint`       | Run ESLint to check code quality         |
| `pnpm run format`     | Format code with Prettier                |
| `pnpm run test`       | Run unit tests                           |
| `pnpm run test:e2e`   | Run end-to-end tests                     |
| `pnpm run test:cov`   | Run tests with coverage report           |
| `pnpm run db:studio`  | Open Drizzle Studio                      |
| `pnpm run db`         | Generate and apply migrations            |
| `pnpm run db:reset`   | Reset database (drop and recreate)       |

## 🗃️ Database Schema

### Users Table

- **id**: UUID (Primary Key)
- **email**: Unique email address
- **password**: Hashed password
- **role**: ADMIN | TEACHER | STUDENT
- **firstName**: User's first name
- **lastName**: User's last name
- **phoneNumber**: Contact number (optional)
- **dateOfBirth**: Date of birth (optional)
- **gender**: MALE | FEMALE | OTHER (optional)
- **address**: Physical address (optional)
- **profilePicture**: Profile image URL (optional)
- **isActive**: Account status
- **lastLogin**: Last login timestamp
- **createdAt**: Account creation timestamp
- **updatedAt**: Last update timestamp

### Other Entities

- **Academic Years**: Manage school years
- **Classes**: Class/grade management
- **Sections**: Section divisions within classes
- **Teachers**: Teacher-specific information

## 🔐 Authentication

The system uses JWT-based authentication with the following features:

- **Password Hashing**: Secure password storage using bcrypt
- **JWT Tokens**: Stateless authentication with 24-hour expiration
- **Role-based Access**: Different permissions for Admin, Teacher, and Student roles
- **Secure Endpoints**: Protected routes with authentication guards

### Authentication Flow

1. User registers/logs in with email and password
2. Server validates credentials and returns JWT token
3. Client includes token in Authorization header for protected requests
4. Server validates token and grants access based on user role

## 🧪 Testing

```bash
# Run unit tests
pnpm run test

# Run tests in watch mode
pnpm run test:watch

# Run e2e tests
pnpm run test:e2e

# Generate coverage report
pnpm run test:cov
```

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Commit your changes**
   ```bash
   git commit -m 'Add some amazing feature'
   ```
4. **Push to the branch**
   ```bash
   git push origin feature/amazing-feature
   ```
5. **Open a Pull Request**

### Development Guidelines

- Follow TypeScript best practices
- Write tests for new features
- Update documentation as needed
- Follow the existing code style
- Use meaningful commit messages

## 📄 License

This project is licensed under the **UNLICENSED** license - see the package.json file for details.

## 👥 Authors

- **dev-sandip** - Initial work and development
- **Sayapatri Group** - Project ownership and guidance

## 🆘 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/sayapatriGroup/SMS/issues) page
2. Create a new issue with detailed information
3. Contact the development team

## 🚧 Roadmap

- [ ] **Student Enrollment System**
- [ ] **Grade Management**
- [ ] **Attendance Tracking**
- [ ] **Parent Portal**
- [ ] **Fee Management**
- [ ] **Timetable Management**
- [ ] **Report Generation**
- [ ] **Mobile Application**

---

**Made with ❤️ by Sayapatri Group**
