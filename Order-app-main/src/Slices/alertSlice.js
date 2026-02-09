import { createSlice } from "@reduxjs/toolkit";
// import React from "react";

const initialState = {
    open:false,
    message:'',
    type:"success"

};




export const alertSlice = createSlice({
  name: "education",
  initialState,
  reducers: {
    setalert: (state, action) => {
      state.open=action.payload.open;
      state.message=action.payload.message;
      state.type=action.payload.type;
      

    },
    getAlert: (state) => {
      return state;
    },
  },
});

// Action creators are generated for each case reducer function
export const {  getAlert,setalert } = alertSlice.actions;

export default alertSlice.reducer;
