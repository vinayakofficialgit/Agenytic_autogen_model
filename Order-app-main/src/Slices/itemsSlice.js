import { createSlice } from '@reduxjs/toolkit'

const initialState = [];

export const itemsSlice = createSlice({
  name: 'items',
  initialState,
  reducers: {
   addtocart:function(state,action){
state.push(action.payload);
   },

  deleteitem:function(state,action){
state.splice(action.payload,1);
  },
  addquantity:function(state,action){
    state.map((ele)=>{
      if(ele.id===action.payload.id){
        ele.quantity=action.payload.qty;
      }else{
        // ele.quantity=1;
        ele.quantity = ele.quantity ? ele.quantity : 1;
      }
     
     
    })

  }
    
  },
})

// Action creators are generated for each case reducer function
export const { addtocart,deleteitem,addquantity} = itemsSlice.actions

export default itemsSlice.reducer