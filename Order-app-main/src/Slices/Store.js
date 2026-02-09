import { configureStore } from '@reduxjs/toolkit'
import itemsSlice from "./itemsSlice";
import AlertSlice from './alertSlice';

export const store = configureStore({
  reducer: {
    itemsSlice,
    AlertSlice,
  },
})