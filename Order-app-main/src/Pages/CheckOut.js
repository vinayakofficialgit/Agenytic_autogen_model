import React, { useState, useEffect } from "react";
import Navbar from "../Components/Navbar";
import { useSelector, useDispatch } from "react-redux";
import { deleteitem, addquantity } from "../Slices/itemsSlice";
import Alertm from "../Components/Alertm";
import {setalert} from "../Slices/alertSlice";


const CheckOut = () => {
  const dispatch = useDispatch();

  const [total, setTotal] = useState();
  const addeditems = useSelector((state) => state.itemsSlice);

  useEffect(() => {
    setTotal(
      addeditems.reduce(
        (acc, curr) => acc + Number(curr.price) * curr.quantity,
        0
      )
    );
  }, [addeditems]);

  const handledelete = (id) => {
    dispatch(deleteitem(id));
  dispatch(setalert({open: true,message:"item removed from Thali",type:"error"}))
  };
  const handleChange = (e,eleId) => {
    const qty=e.target.value;
    dispatch(addquantity({id:eleId,qty:qty}));
    console.log(eleId)
  };

const orderClick=()=>{
  dispatch(setalert({open: true,message:"Order Placed",type:"success"}))


}

  return (
    <div className="checkoutContainer">
      <Navbar />
      <h1 style={{ textAlign: "center" }}>Summary Of Your Thali</h1>
      <div className="thaliItems">
        <table
          className="table table-light"
          style={{ width: "80%", margin: "auto", backgroundColor: "yellow", boxShadow:" 0 0 10px rgba(14, 13, 13, 0.959)" }}
        >
          <thead>
            <tr>
              <th>Index No</th>
              <th>Image</th>
              <th>Name</th>
              <th>Quantity</th>
              <th>Total</th>
              <th></th>
            </tr>
          </thead>

          <tbody>
            {addeditems.map((ele, index) => {
              return (
                <tr key={ele.id}>
                  <td>{index + 1}</td>
                  <td>
                    <img
                      src={ele.image}
                      alt=""
                      className="img-fluid"
                      style={{ width: "50px", height: "50px" }}
                    />
                  </td>
                  <td>{ele.name}</td>
                  <td>
                    <span>
                     
                <select name="rating" id="cars"  onChange={(e)=>handleChange(e,ele.id)}>
                  <option disabled>quantity</option>
                  <option value={1}>1</option>
                  <option value={2}>2</option>
                  <option value={3}>3</option>
                  <option value={4}>4</option>
                  <option value={5}>5</option>

                </select>
                    </span>
                  </td>
                  <td>
                  <span>total {ele.price*parseInt(ele.quantity)}</span>
                  </td>

                  <td>
                    <button
                      className="btn btn-danger"
                      onClick={() => handledelete(index)}
                    >
                      remove
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>

          <tfoot>
            <tr>
              <td>Total</td>
              <td></td>
              <td></td>
              <td></td>
              <td>Rs-{total}</td>
              <td></td>
            </tr>
          </tfoot>
        </table>
      </div>
      <button
        className="btn btn-success "
        style={{ float: "right", marginRight: "15%" }}
        onClick={orderClick}
      >
        Order Now
      </button>
      <Alertm />
    </div>
  );
};

export default CheckOut;
