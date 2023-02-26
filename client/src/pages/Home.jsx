import React, { useState, useEffect } from 'react'
import { DisplayCampaigns } from '../components'

import { useStateContext } from '../context'

const Home = () => {
  const [isLoading, setIsLoading] = useState(false)
  const [campaigns, setCampaigns] = useState([])
  const {address,contract, getAllCampaigns} = useStateContext();
  

  const fetchCampaigns = async () => {
    try {

      console.log('method called')
      setIsLoading(true)
      const data = await getAllCampaigns()
      setCampaigns(data)
      setIsLoading(false)
    } catch (error) {
      console.log(error)
    }
  }

  useEffect(() => {
    if (contract) fetchCampaigns()
  }, [address, contract])

  return <DisplayCampaigns
    title="All Campaigns"
    isLoading= {isLoading}
    campaigns = {campaigns}
  />
}

export default Home
