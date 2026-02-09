import React,{} from 'react';
import {useSelector} from "react-redux";

const Thali = () => {
  const addeditems=useSelector((state)=>state.itemsSlice);
  // const [added,setadded]=useState(addeditems)
  return (
    <div className='addeditemsContainer' >
      <h4 style={{textAlign:"center",backgroundColor:"white"}}>Your Items in Thali</h4>
      <div className="itemscontainer" style={{backgroundColor:"white"}}>
        <div className="inn">
          {  addeditems.length===0?<h2>No items in Your Thali add Some Items</h2>:""}
          {
            addeditems.map((ele,i)=>{
              return(
              
                <div className="card" style={{width: "18rem",height:"300px"}} key={i}>
                <img src={ele.image} className="card-img-top" alt="..." height={"200px"}/>
                <div className="card-body">
                <h5 className="card-text">{ele.name}</h5>

                  <p className="card-text">{ele.description}</p>

                </div>
              </div>
              )
             
            })
          }




      </div>
      </div>
    </div>
  )
}

export default Thali
