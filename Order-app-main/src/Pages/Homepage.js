import React from 'react'
import Alertm from '../Components/Alertm'
import Itemssection from '../Components/Itemssection'
import Navbar from '../Components/Navbar'
import Thali from '../Components/Thali'

const Homepage = () => {
  return (
    <div>
      <Navbar/>
      <Thali/>
      <Itemssection/>
      <Alertm/>
    </div>
  )
}

export default Homepage
