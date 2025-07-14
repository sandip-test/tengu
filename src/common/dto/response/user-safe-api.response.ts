// src/helpers/with-safe-user-response.ts

import { ApiResponse } from '@/common/dto/response/api-response';
import { USERS } from '@/db/schema';
import omit from '@/helpers/omit';

export const SafeUserAPIResponse = (user: USERS) => {
  if (!user) return new ApiResponse(null); // or handle user-not-found case
  const safeUser = omit(user, ['password']);
  return new ApiResponse(safeUser);
};
