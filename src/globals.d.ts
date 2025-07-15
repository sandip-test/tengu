// User type for request.user (set by auth guard)
export interface AuthUser {
  id: string;
  email: string;
}

// Extend Express Request to include user property
declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}
