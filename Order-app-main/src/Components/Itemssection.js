import React, { useState } from "react";
import { MEALS } from "../Meals/meals";
import { useSelector, useDispatch } from "react-redux";
import { addtocart, deleteitem } from "../Slices/itemsSlice";
import { setalert } from "../Slices/alertSlice";
import { useNavigate } from "react-router-dom";

const Itemssection = () => {
  const navigate = useNavigate();
  const items = useSelector((state) => state.itemsSlice);
  const dispatch = useDispatch();
  const [mealslist, setmilslist] = useState(MEALS);
  const filtermenu = (category) => {
    const filtered = MEALS.filter((ele) => ele.category === category);
    setmilslist(filtered);
  };
  const setdefault = () => {
    setmilslist(MEALS);
  };

  const addcart = (item) => {
    dispatch(addtocart(item));
    dispatch(
      setalert({
        open: true,
        message: "item added successfully",
        type: "success",
      })
    );
  };

  const remove = (id) => {
    let index = 0;
    for (let i = 0; i < items.length; i++) {
      if (items[i].id === id) {
        index = i;
      }
    }
    dispatch(deleteitem(index));
    dispatch(
      setalert({
        open: true,
        message: "item removed from Thali",
        type: "error",
      })
    );
  };
  const handlecheckout = () => {
    if (items.length < 2) {
      dispatch(
        setalert({
          open: true,
          message: "You need to add atleast two item in thali",
          type: "error",
        })
      );
    } else {
      navigate("/checkout");
    }
  };

  return (
    <div >
      <h1 style={{ textAlign: "center" }}>Todays Special</h1>
      <div
        className="buttonContainer"
        style={{
          width: "50%",
          margin: "auto",
          marginBottom: "30px",
          display: "flex",
          justifyContent: "space-around",
          flexWrap:"wrap"
        }}
      >
        <button className="btn btn-warning my-2" onClick={setdefault}>
          All Dishes
        </button>

        <button
          className="btn btn-warning my-2"
          onClick={() => filtermenu("chapati")}
        >
          chapati
        </button>
        <button
          className="btn btn-warning"
          onClick={() => filtermenu("pickle")}
        >
          Plicke
        </button>
        <button className="btn btn-warning my-2" onClick={() => filtermenu("curd")}>
          Curd
        </button>
        <button className="btn btn-warning my-2" onClick={() => filtermenu("sweet")}>
          sweet
        </button>
        <button className="btn btn-warning my-2" onClick={() => filtermenu("daal")}>
          daal
        </button>
        <button
          className="btn btn-warning my-2"
          onClick={() => filtermenu("paneer dish")}
        >
          Paneer dish
        </button>
      </div>
      <div>
        <div
          className="items "
          style={{
            backgroundColor: "white",
            width: "90%",
            margin: "auto",
            display: "flex",
            padding: "3%",
            justifyContent: "space-around",
            flexWrap: "wrap",
            boxShadow:" 0 0 10px rgba(14, 13, 13, 0.959)"
          }}
        >
          {mealslist.map((ele, index) => {
            return (
              <div
                className="card "
                style={{ width: "18rem", margin: "20px" }}
                key={index}
              >
                <img
                  src={ele.image}
                  className="card-img-top"
                  alt="..."
                  height={"150px"}
                />
                <div className="card-body">
                  <h4 className="card-text">{ele.name}.</h4>
                  <h4>rs.{ele.price}</h4>
                  <p>{ele.description}</p>
                  {items.some((p) => p.id === ele.id) ? (
                    <button
                      className="btn btn-danger"
                      onClick={() => remove(ele.id)}
                    >
                      Remove
                    </button>
                  ) : (
                    <button
                      className="btn btn-primary"
                      onClick={() => addcart(ele)}
                    >
                      Add to Thali
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        <button className="btn btn-warning cbutton" onClick={handlecheckout}>
          Check Out
        </button>
      </div>
    </div>
  );
};

export default Itemssection;
