import { USERS } from './db/schema';

declare global {
  namespace Express {
    interface Request {
      user?: USERS;
    }
  }
}
